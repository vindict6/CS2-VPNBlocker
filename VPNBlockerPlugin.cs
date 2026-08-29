using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using CounterStrikeSharp.API;
using CounterStrikeSharp.API.Core;
using CounterStrikeSharp.API.Core.Attributes.Registration;
using CounterStrikeSharp.API.Modules.Admin;
using CounterStrikeSharp.API.Modules.Commands;
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
    public override string ModuleVersion => "1.4.0";
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
    private string WhitelistPath = "";
    private string LegacyCachePath => Path.Combine(ModuleDirectory, "ipcache.json");

    // SteamID64s allowed to join even from blocked IPs.
    private readonly ConcurrentDictionary<ulong, byte> _whitelist = new();

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
        [JsonPropertyName("isp")] public string? Isp { get; set; }
        [JsonPropertyName("org")] public string? Org { get; set; }
        [JsonPropertyName("as")] public string? As { get; set; }
    }

    // ip-api marks Google Fiber (AS16591) as "hosting" because it belongs to
    // Google, but it's a residential ISP — don't block it.
    private static bool IsResidentialFiber(IpApiResponse data) =>
        (data.As?.StartsWith("AS16591 ", StringComparison.OrdinalIgnoreCase) ?? false)
        || (data.Isp?.Contains("Google Fiber", StringComparison.OrdinalIgnoreCase) ?? false)
        || (data.Org?.Contains("Google Fiber", StringComparison.OrdinalIgnoreCase) ?? false);

    public void OnConfigParsed(VPNBlockerConfig config) => Config = config;

    public override void Load(bool hotReload)
    {
        _cts = new CancellationTokenSource();
        ConfigDir = Path.Combine(
            Server.GameDirectory, "csgo", "addons", "counterstrikesharp", "configs", "plugins", "CS2-VPNBlocker");
        CachePath = Path.Combine(ConfigDir, "ipcache.json");
        WhitelistPath = Path.Combine(ConfigDir, "whitelist.json");
        LoadCacheFromDisk();
        LoadWhitelistFromDisk();

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

        var steamId = player.AuthorizedSteamID?.SteamId64 ?? player.SteamID;
        if (_whitelist.ContainsKey(steamId))
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
        var url = $"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,org,as";
        using var response = await Http.GetAsync(url, timeout.Token);
        if (!response.IsSuccessStatusCode)
            return null;

        var body = await response.Content.ReadAsStringAsync(timeout.Token);
        var data = JsonSerializer.Deserialize<IpApiResponse>(body);
        if (data?.Status != "success")
            return null;

        var reasons = new List<string>(2);
        if (Config.BlockProxies && data.Proxy) reasons.Add("proxy/vpn");
        if (Config.BlockHosting && data.Hosting && !IsResidentialFiber(data)) reasons.Add("datacenter");

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

            var steamId = player.AuthorizedSteamID?.SteamId64 ?? player.SteamID;
            if (_whitelist.ContainsKey(steamId))
            {
                Logger.LogInformation("[VPNBlocker] Whitelisted user '{0}' ({1}) allowed through despite: {2}", player.PlayerName, ip, reason);
                return;
            }

            if (AdminManager.PlayerHasPermissions(player, Config.AdminBypassFlag))
            {
                Logger.LogInformation("[VPNBlocker] Admin '{0}' ({1}) allowed through despite: {2}", player.PlayerName, ip, reason);
                return;
            }

            Logger.LogInformation("[VPNBlocker] Kicking '{0}' ({1}, {2}): {3} (attempt #{4})", player.PlayerName, ip, steamId, reason, attempts);
            Server.ExecuteCommand($"kickid {player.UserId}");
            NotifyAdmins(ip, steamId, reason, attempts);
        });
    }

    // Must be called on the game thread.
    private void NotifyAdmins(string ip, ulong steamId, string reason, int attempts)
    {
        foreach (var player in Utilities.GetPlayers())
        {
            if (!player.IsValid || player.IsBot || player.IsHLTV)
                continue;
            if (!AdminManager.PlayerHasPermissions(player, Config.AdminNotifyFlag))
                continue;

            player.PrintToChat($" {ChatColors.Red}[VPNBlocker]{ChatColors.Default} Blocked {ChatColors.Yellow}{ip}{ChatColors.Default} ({reason}) — attempt #{attempts}");
            player.PrintToChat($" {ChatColors.Red}[VPNBlocker]{ChatColors.Default} SteamID {ChatColors.Yellow}{steamId}{ChatColors.Default} — !unblock {steamId} to allow");
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

    [ConsoleCommand("css_unblock", "Allow a SteamID to join even from a VPN/datacenter IP")]
    [RequiresPermissions("@css/ban")]
    [CommandHelper(minArgs: 1, usage: "<steamid64 | STEAM_X:Y:Z | [U:1:Z]>", whoCanExecute: CommandUsage.CLIENT_AND_SERVER)]
    public void OnUnblockCommand(CCSPlayerController? caller, CommandInfo command)
    {
        if (!TryParseSteamId(command.GetArg(1), out var steamId))
        {
            command.ReplyToCommand($" {ChatColors.Red}[VPNBlocker]{ChatColors.Default} Could not parse SteamID '{command.GetArg(1)}'.");
            return;
        }

        if (_whitelist.TryAdd(steamId, 0))
        {
            SaveWhitelistToDisk();
            Logger.LogInformation("[VPNBlocker] {0} whitelisted {1}", caller?.PlayerName ?? "Console", steamId);
            command.ReplyToCommand($" {ChatColors.Green}[VPNBlocker]{ChatColors.Default} {steamId} can now join from any IP.");
        }
        else
        {
            command.ReplyToCommand($" {ChatColors.Green}[VPNBlocker]{ChatColors.Default} {steamId} is already unblocked.");
        }
    }

    [ConsoleCommand("css_reblock", "Remove a SteamID from the VPNBlocker whitelist")]
    [RequiresPermissions("@css/ban")]
    [CommandHelper(minArgs: 1, usage: "<steamid64 | STEAM_X:Y:Z | [U:1:Z]>", whoCanExecute: CommandUsage.CLIENT_AND_SERVER)]
    public void OnReblockCommand(CCSPlayerController? caller, CommandInfo command)
    {
        if (!TryParseSteamId(command.GetArg(1), out var steamId))
        {
            command.ReplyToCommand($" {ChatColors.Red}[VPNBlocker]{ChatColors.Default} Could not parse SteamID '{command.GetArg(1)}'.");
            return;
        }

        if (_whitelist.TryRemove(steamId, out _))
        {
            SaveWhitelistToDisk();
            Logger.LogInformation("[VPNBlocker] {0} removed {1} from whitelist", caller?.PlayerName ?? "Console", steamId);
            command.ReplyToCommand($" {ChatColors.Green}[VPNBlocker]{ChatColors.Default} {steamId} is blockable again.");
        }
        else
        {
            command.ReplyToCommand($" {ChatColors.Green}[VPNBlocker]{ChatColors.Default} {steamId} was not on the whitelist.");
        }
    }

    [ConsoleCommand("css_recheck", "Forget a cached IP verdict so it gets looked up again on next connect")]
    [RequiresPermissions("@css/ban")]
    [CommandHelper(minArgs: 1, usage: "<ip>", whoCanExecute: CommandUsage.CLIENT_AND_SERVER)]
    public void OnRecheckCommand(CCSPlayerController? caller, CommandInfo command)
    {
        var ip = command.GetArg(1).Trim();
        if (_cache.TryRemove(ip, out _))
        {
            var saveToken = _cts.Token;
            _ = Task.Run(() => SaveCacheToDiskAsync(saveToken), saveToken);
            Logger.LogInformation("[VPNBlocker] {0} purged {1} from the IP cache", caller?.PlayerName ?? "Console", ip);
            command.ReplyToCommand($" {ChatColors.Green}[VPNBlocker]{ChatColors.Default} {ip} forgotten — it will be re-checked on next connect.");
        }
        else
        {
            command.ReplyToCommand($" {ChatColors.Green}[VPNBlocker]{ChatColors.Default} {ip} is not in the cache.");
        }
    }

    private const ulong SteamId64Base = 76561197960265728UL;

    private static bool TryParseSteamId(string input, out ulong steamId64)
    {
        steamId64 = 0;
        input = input.Trim();

        // SteamID64
        if (ulong.TryParse(input, out var id64) && id64 > SteamId64Base)
        {
            steamId64 = id64;
            return true;
        }

        // [U:1:144697568] / U:1:144697568
        var s = input.TrimStart('[').TrimEnd(']');
        if (s.StartsWith("U:1:", StringComparison.OrdinalIgnoreCase)
            && uint.TryParse(s[4..], out var accountId))
        {
            steamId64 = SteamId64Base + accountId;
            return true;
        }

        // STEAM_X:Y:Z
        if (s.StartsWith("STEAM_", StringComparison.OrdinalIgnoreCase))
        {
            var parts = s[6..].Split(':');
            if (parts.Length == 3
                && uint.TryParse(parts[1], out var y) && y <= 1
                && uint.TryParse(parts[2], out var z))
            {
                steamId64 = SteamId64Base + z * 2UL + y;
                return true;
            }
        }

        return false;
    }

    private void LoadWhitelistFromDisk()
    {
        try
        {
            if (!File.Exists(WhitelistPath))
                return;

            var ids = JsonSerializer.Deserialize<List<ulong>>(File.ReadAllText(WhitelistPath));
            if (ids == null)
                return;

            foreach (var id in ids)
                _whitelist.TryAdd(id, 0);
            Logger.LogInformation("[VPNBlocker] Loaded {0} whitelisted SteamIDs.", _whitelist.Count);
        }
        catch (Exception ex)
        {
            Logger.LogError("[VPNBlocker] Failed to load whitelist: {0}", ex.Message);
        }
    }

    // Called from the game thread (commands); the file is tiny, so a
    // synchronous write under the save lock is fine.
    private void SaveWhitelistToDisk()
    {
        _saveLock.Wait();
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var ids = _whitelist.Keys.OrderBy(id => id).ToList();
            File.WriteAllText(WhitelistPath, JsonSerializer.Serialize(ids, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            Logger.LogError("[VPNBlocker] Failed to save whitelist: {0}", ex.Message);
        }
        finally
        {
            _saveLock.Release();
        }
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
