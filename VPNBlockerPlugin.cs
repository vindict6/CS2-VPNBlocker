using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using CounterStrikeSharp.API;
using CounterStrikeSharp.API.Core;
using CounterStrikeSharp.API.Modules.Admin;
using CounterStrikeSharp.API.Modules.Utils;
using Microsoft.Extensions.Logging;

namespace VPNBlocker;

public class VPNBlockerConfig : BasePluginConfig
{
    [JsonPropertyName("block_proxies")] public bool BlockProxies { get; set; } = true;
    [JsonPropertyName("block_hosting")] public bool BlockHosting { get; set; } = true;
    [JsonPropertyName("lookup_timeout_seconds")] public int LookupTimeoutSeconds { get; set; } = 5;
    [JsonPropertyName("admin_notify_flag")] public string AdminNotifyFlag { get; set; } = "@css/ban";
    [JsonPropertyName("admin_bypass_flag")] public string AdminBypassFlag { get; set; } = "@css/ban";
    [JsonPropertyName("announce_on_load")] public bool AnnounceOnLoad { get; set; } = true;
}

public class VPNBlockerPlugin : BasePlugin, IPluginConfig<VPNBlockerConfig>
{
    public override string ModuleName => "CS2 VPN Blocker";
    public override string ModuleVersion => "1.2.0";
    public override string ModuleAuthor => "vindict6";
    public override string ModuleDescription => "Kicks clients connecting from VPN/proxy/datacenter IPs (via ip-api.com).";

    public VPNBlockerConfig Config { get; set; } = new();

    // Shared across hot reloads; never disposed on purpose.
    private static readonly HttpClient Http = new();

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly ConcurrentDictionary<string, byte> _pending = new();
    private readonly SemaphoreSlim _saveLock = new(1, 1);
    private CancellationTokenSource _cts = new();

    // Resolved once in Load() on the main thread: Server.GameDirectory is a
    // native call and must not be touched from background save tasks.
    private string ConfigDir = "";
    private string CachePath = "";
    private string LegacyCachePath => Path.Combine(ModuleDirectory, "ipcache.json");

    private sealed class CacheEntry
    {
        [JsonPropertyName("blocked")] public bool Blocked { get; set; }
        [JsonPropertyName("reason")] public string? Reason { get; set; }
        [JsonPropertyName("checked_at")] public DateTimeOffset CheckedAt { get; set; }
        [JsonInclude][JsonPropertyName("attempts")] public int Attempts;
    }

    private sealed class IpApiResponse
    {
        [JsonPropertyName("status")] public string? Status { get; set; }
        [JsonPropertyName("proxy")] public bool Proxy { get; set; }
        [JsonPropertyName("hosting")] public bool Hosting { get; set; }
    }

    public void OnConfigParsed(VPNBlockerConfig config) => Config = config;

    public override void Load(bool hotReload)
    {
        _cts = new CancellationTokenSource();
        ConfigDir = Path.Combine(
            Server.GameDirectory, "csgo", "addons", "counterstrikesharp", "configs", "plugins", "CS2-VPNBlocker");
        CachePath = Path.Combine(ConfigDir, "ipcache.json");
        LoadCacheFromDisk();

        RegisterListener<Listeners.OnClientConnected>(slot => CheckSlot(slot));

        if (hotReload)
        {
            foreach (var player in Utilities.GetPlayers())
            {
                if (player.IsValid && !player.IsBot)
                    CheckSlot(player.Slot);
            }
        }

        if (Config.AnnounceOnLoad)
        {
            Server.NextFrame(() =>
                Server.PrintToChatAll($" {ChatColors.Green}[VPNBlocker]{ChatColors.Default} VPNBlocker has been {ChatColors.Red}armed{ChatColors.Default}."));
        }
    }

    public override void Unload(bool hotReload)
    {
        _cts.Cancel();
        _cts.Dispose();
        SaveCacheToDiskBlocking();
    }

    private void CheckSlot(int slot)
    {
        var player = Utilities.GetPlayerFromSlot(slot);
        if (player == null || !player.IsValid || player.IsBot || player.IsHLTV)
            return;

        var ip = player.IpAddress?.Split(':')[0];
        if (string.IsNullOrEmpty(ip) || IsPrivateOrLocal(ip))
            return;

        if (_cache.TryGetValue(ip, out var entry))
        {
            var attempts = Interlocked.Increment(ref entry.Attempts);
            if (entry.Blocked)
            {
                KickNextFrame(slot, ip, entry.Reason ?? "vpn/hosting", attempts);
                var saveToken = _cts.Token;
                _ = Task.Run(() => SaveCacheToDiskAsync(saveToken), saveToken);
            }
            return;
        }

        // Only one in-flight lookup per IP.
        if (!_pending.TryAdd(ip, 0))
            return;

        var token = _cts.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                var result = await LookupAsync(ip, token);
                if (result == null)
                    return; // lookup failed: fail open, no caching

                result.Attempts = 1;
                _cache[ip] = result;
                if (result.Blocked)
                    KickNextFrame(slot, ip, result.Reason ?? "vpn/hosting", 1);
                await SaveCacheToDiskAsync(token);
            }
            catch (OperationCanceledException)
            {
                // plugin unloading
            }
            catch (Exception ex)
            {
                Logger.LogError("[VPNBlocker] Lookup for {0} failed: {1}", ip, ex.Message);
            }
            finally
            {
                _pending.TryRemove(ip, out _);
            }
        }, token);
    }

    private async Task<CacheEntry?> LookupAsync(string ip, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, Config.LookupTimeoutSeconds)));

        // Free ip-api.com endpoint (HTTP only, 45 req/min — the cache keeps us far below that).
        var url = $"http://ip-api.com/json/{ip}?fields=status,proxy,hosting";
        using var response = await Http.GetAsync(url, timeout.Token);
        if (!response.IsSuccessStatusCode)
            return null;

        var body = await response.Content.ReadAsStringAsync(timeout.Token);
        var data = JsonSerializer.Deserialize<IpApiResponse>(body);
        if (data?.Status != "success")
            return null;

        var reasons = new List<string>(2);
        if (Config.BlockProxies && data.Proxy) reasons.Add("proxy/vpn");
        if (Config.BlockHosting && data.Hosting) reasons.Add("datacenter");

        return new CacheEntry
        {
            Blocked = reasons.Count > 0,
            Reason = reasons.Count > 0 ? string.Join("+", reasons) : null,
            CheckedAt = DateTimeOffset.UtcNow,
        };
    }

    private void KickNextFrame(int slot, string ip, string reason, int attempts)
    {
        var token = _cts.Token;
        Server.NextFrame(() =>
        {
            if (token.IsCancellationRequested)
                return;

            var player = Utilities.GetPlayerFromSlot(slot);
            if (player == null || !player.IsValid || player.IsBot)
                return;

            // Make sure the slot wasn't reused by a different connection.
            if (player.IpAddress?.Split(':')[0] != ip)
                return;

            if (AdminManager.PlayerHasPermissions(player, Config.AdminBypassFlag))
            {
                Logger.LogInformation("[VPNBlocker] Admin '{0}' ({1}) allowed through despite: {2}", player.PlayerName, ip, reason);
                return;
            }

            Logger.LogInformation("[VPNBlocker] Kicking '{0}' ({1}): {2} (attempt #{3})", player.PlayerName, ip, reason, attempts);
            Server.ExecuteCommand($"kickid {player.UserId}");
            NotifyAdmins(ip, reason, attempts);
        });
    }

    // Must be called on the game thread.
    private void NotifyAdmins(string ip, string reason, int attempts)
    {
        foreach (var player in Utilities.GetPlayers())
        {
            if (!player.IsValid || player.IsBot || player.IsHLTV)
                continue;
            if (!AdminManager.PlayerHasPermissions(player, Config.AdminNotifyFlag))
                continue;

            player.PrintToChat($" {ChatColors.Red}[VPNBlocker]{ChatColors.Default} Blocked {ChatColors.Yellow}{ip}{ChatColors.Default} ({reason}) — attempt #{attempts}");
        }
    }

    private static bool IsPrivateOrLocal(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr))
            return true;
        if (IPAddress.IsLoopback(addr))
            return true;

        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 4)
            return false; // IPv6: let the API decide

        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254)
            || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127);
    }

    private void LoadCacheFromDisk()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);

            var path = File.Exists(CachePath) ? CachePath
                : File.Exists(LegacyCachePath) ? LegacyCachePath
                : null;
            if (path == null)
                return;

            var data = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(File.ReadAllText(path));
            if (data == null)
                return;

            foreach (var (ip, entry) in data)
                _cache[ip] = entry;
            Logger.LogInformation("[VPNBlocker] Loaded {0} cached IP entries.", _cache.Count);
        }
        catch (Exception ex)
        {
            Logger.LogError("[VPNBlocker] Failed to load IP cache: {0}", ex.Message);
        }
    }

    private async Task SaveCacheToDiskAsync(CancellationToken token)
    {
        if (CachePath.Length == 0)
            return;

        await _saveLock.WaitAsync(token);
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var snapshot = _cache.ToDictionary(kv => kv.Key, kv => kv.Value);
            var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(CachePath, json, token);
        }
        finally
        {
            _saveLock.Release();
        }
    }

    private void SaveCacheToDiskBlocking()
    {
        if (CachePath.Length == 0)
            return;

        _saveLock.Wait();
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var snapshot = _cache.ToDictionary(kv => kv.Key, kv => kv.Value);
            File.WriteAllText(CachePath, JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            Logger.LogError("[VPNBlocker] Failed to save IP cache: {0}", ex.Message);
        }
        finally
        {
            _saveLock.Release();
        }
    }
}
