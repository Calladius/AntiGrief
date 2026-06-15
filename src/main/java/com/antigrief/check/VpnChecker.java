package com.antigrief.check;

import com.antigrief.AntiGriefPlugin;
import com.antigrief.config.ConfigManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

// проверка на vpn/proxy/tor + определение страны
// приоритет: proxycheck.io → ip-api.com → iphub.info
public class VpnChecker {

    private final ConfigManager configManager;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final java.util.concurrent.ConcurrentHashMap<String, VpnResult> cache = new java.util.concurrent.ConcurrentHashMap<>();
    private final AntiGriefPlugin plugin;

    public VpnChecker(ConfigManager configManager, AntiGriefPlugin plugin) {
        this.configManager = configManager;
        this.plugin = plugin;

        HttpClient.Builder clientBuilder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10));

        // socks5 если настроен
        String proxyHost = configManager.getProxyHost();
        int proxyPort = configManager.getProxyPort();
        if (proxyHost != null && !proxyHost.isEmpty() && proxyPort > 0) {
            clientBuilder.proxy(ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort)));
        }

        this.httpClient = clientBuilder.build();
        this.objectMapper = new ObjectMapper();
    }

    public static class VpnResult {
        public boolean isVpn;
        public boolean isError;
        public String country;
        public String isp;
        public String asn;   // номер автономной системы (провайдер), напр. "12389"
        public String vpnType; // "VPN", "Proxy", "Tor", "Hosting" или null

        public VpnResult(boolean isVpn, boolean isError, String country, String isp) {
            this.isVpn = isVpn; this.isError = isError; this.country = country; this.isp = isp; this.vpnType = null; this.asn = null;
        }

        public VpnResult(boolean isVpn, boolean isError, String country, String isp, String vpnType) {
            this.isVpn = isVpn; this.isError = isError; this.country = country; this.isp = isp; this.vpnType = vpnType; this.asn = null;
        }

        public VpnResult(boolean isVpn, boolean isError, String country, String isp, String vpnType, String asn) {
            this.isVpn = isVpn; this.isError = isError; this.country = country; this.isp = isp; this.vpnType = vpnType; this.asn = asn;
        }
    }

    public CompletableFuture<VpnResult> checkAsync(String ip) {
        VpnResult cached = cache.get(ip);
        if (cached != null) return CompletableFuture.completedFuture(cached);

        if (isLocalIp(ip)) {
            VpnResult result = new VpnResult(false, false, "LOCAL", "LOCAL");
            cache.put(ip, result);
            return CompletableFuture.completedFuture(result);
        }

        String proxycheckKey = configManager.getProxycheckApiKey();
        return checkProxycheckAsync(ip, proxycheckKey != null ? proxycheckKey : "");
    }

    public VpnResult check(String ip) {
        try {
            return checkAsync(ip).get();
        } catch (Exception e) {
            plugin.getLogger().warning("[VpnChecker] ошибка проверки IP=" + ip + ": " + e.getMessage());
            return new VpnResult(false, true, "???", "???");
        }
    }

    // proxycheck.io v3 — основной, лучшая детекция
    private CompletableFuture<VpnResult> checkProxycheckAsync(String ip, String apiKey) {
        String url = "https://proxycheck.io/v3/" + ip;
        if (apiKey != null && !apiKey.isEmpty()) {
            url += "?key=" + apiKey;
        }

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(8))
            .GET()
            .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenApply(response -> {
                try {
                    JsonNode json = objectMapper.readTree(response.body());
                    String status = json.path("status").asText("");

                    if (!"ok".equals(status)) {
                        plugin.getLogger().warning("[VpnChecker] proxycheck ошибка для IP=" + ip + ": " + status);
                        return tryFallbackSync(ip);
                    }

                    JsonNode ipNode = json.path(ip);
                    String country = ipNode.path("location").path("country_code").asText("???");
                    String isp = ipNode.path("network").path("provider").asText("???");
                    String asn = ipNode.path("network").path("asn").asText(null);
                    // нормализуем: "AS12345" → "12345"
                    if (asn != null && asn.toUpperCase().startsWith("AS")) {
                        asn = asn.substring(2);
                    }
                    String networkType = ipNode.path("network").path("type").asText("");

                    JsonNode detections = ipNode.path("detections");
                    boolean isVpn = detections.path("vpn").asBoolean(false);
                    boolean isProxy = detections.path("proxy").asBoolean(false);
                    boolean isTor = detections.path("tor").asBoolean(false);
                    boolean isHosting = detections.path("hosting").asBoolean(false);
                    int risk = detections.path("risk").asInt(0);

                    boolean isBlocked = isVpn || isProxy || isTor || isHosting;

                    String vpnType = null;
                    if (isVpn) vpnType = "VPN";
                    else if (isTor) vpnType = "Tor";
                    else if (isProxy) vpnType = "Proxy";
                    else if (isHosting) vpnType = "Hosting";

                    plugin.getLogger().info("[VpnChecker] proxycheck: " + ip
                        + " country=" + country + " asn=" + asn + " vpn=" + isVpn + " proxy=" + isProxy
                        + " tor=" + isTor + " hosting=" + isHosting + " risk=" + risk
                        + " type=" + networkType + " isp=" + isp + " → blocked=" + isBlocked);

                    VpnResult result = new VpnResult(isBlocked, false, country, isp, vpnType, asn);
                    cache.put(ip, result);
                    return result;
                } catch (Exception e) {
                    plugin.getLogger().warning("[VpnChecker] ошибка парсинга proxycheck для IP=" + ip + ": " + e.getMessage());
                    return tryFallbackSync(ip);
                }
            })
            .exceptionally(ex -> {
                plugin.getLogger().warning("[VpnChecker] proxycheck недоступен для IP=" + ip + ": " + ex.getMessage());
                return tryFallbackSync(ip);
            });
    }

    // фоллбэк: ip-api.com → iphub.info
    private VpnResult tryFallbackSync(String ip) {
        try {
            VpnResult result = checkIpApiSync(ip);
            if (result != null) return result;
        } catch (Exception e) {
            plugin.getLogger().warning("[VpnChecker] ip-api недоступен для IP=" + ip + ": " + e.getMessage());
        }

        String iphubKey = configManager.getIphubApiKey();
        if (iphubKey != null && !iphubKey.isEmpty()) {
            try {
                return checkIphubSync(ip, iphubKey);
            } catch (Exception e) {
                plugin.getLogger().warning("[VpnChecker] iphub недоступен для IP=" + ip + ": " + e.getMessage());
            }
        }

        // все api недоступны — пропускаем
        plugin.getLogger().warning("[VpnChecker] все API недоступны для IP=" + ip + " — пропуск");
        VpnResult result = new VpnResult(false, true, "???", "???");
        cache.put(ip, result);
        return result;
    }

    private CompletableFuture<VpnResult> checkIpApiAsync(String ip) {
        String url = "http://ip-api.com/json/" + ip + "?fields=status,message,countryCode,proxy,hosting,isp,as";

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET().build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
            .thenApply(response -> {
                try {
                    JsonNode json = objectMapper.readTree(response.body());
                    if (!"success".equals(json.path("status").asText(""))) {
                        return tryFallbackSync(ip);
                    }
                    String country = json.path("countryCode").asText("???");
                    boolean proxy = json.path("proxy").asBoolean(false);
                    boolean hosting = json.path("hosting").asBoolean(false);
                    String isp = json.path("isp").asText("???");
                    String asnRaw = json.path("as").asText(null);
                    // нормализуем: "AS12345 Beeline" → "12345"
                    String asn = null;
                    if (asnRaw != null && !asnRaw.isEmpty()) {
                        String[] parts = asnRaw.split("\\s+", 2);
                        String asnNum = parts[0];
                        if (asnNum.toUpperCase().startsWith("AS")) {
                            asn = asnNum.substring(2);
                        } else {
                            asn = asnNum;
                        }
                    }
                    boolean isVpn = proxy || hosting;
                    String vpnType = isVpn ? (hosting ? "Hosting" : (proxy ? "Proxy" : null)) : null;

                    VpnResult result = new VpnResult(isVpn, false, country, isp, vpnType, asn);
                    cache.put(ip, result);
                    return result;
                } catch (Exception e) {
                    return tryFallbackSync(ip);
                }
            })
            .exceptionally(ex -> tryFallbackSync(ip));
    }

    private VpnResult checkIpApiSync(String ip) throws Exception {
        String url = "http://ip-api.com/json/" + ip + "?fields=status,message,countryCode,proxy,hosting,isp,as";

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url)).timeout(Duration.ofSeconds(5)).GET().build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        JsonNode json = objectMapper.readTree(response.body());

        if (!"success".equals(json.path("status").asText(""))) return null;

        String country = json.path("countryCode").asText("???");
        boolean proxy = json.path("proxy").asBoolean(false);
        boolean hosting = json.path("hosting").asBoolean(false);
        String isp = json.path("isp").asText("???");
        String asnRaw = json.path("as").asText(null);
        // нормализуем: "AS12345 Beeline" → "12345"
        String asn = null;
        if (asnRaw != null && !asnRaw.isEmpty()) {
            String[] parts = asnRaw.split("\\s+", 2);
            String asnNum = parts[0];
            if (asnNum.toUpperCase().startsWith("AS")) {
                asn = asnNum.substring(2);
            } else {
                asn = asnNum;
            }
        }
        boolean isVpn = proxy || hosting;
        String vpnType = isVpn ? (hosting ? "Hosting" : (proxy ? "Proxy" : null)) : null;

        plugin.getLogger().info("[VpnChecker] ip-api (резерв): " + ip
            + " country=" + country + " asn=" + asn + " proxy=" + proxy + " hosting=" + hosting + " isp=" + isp);

        VpnResult result = new VpnResult(isVpn, false, country, isp, vpnType, asn);
        cache.put(ip, result);
        return result;
    }

    private VpnResult checkIphubSync(String ip, String apiKey) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://v2.api.iphub.info/ip/" + ip))
            .header("X-Key", apiKey)
            .timeout(Duration.ofSeconds(5)).GET().build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        JsonNode json = objectMapper.readTree(response.body());
        int block = json.path("block").asInt(0);
        String country = json.path("countryCode").asText("???");
        String isp = json.path("isp").asText("???");

        boolean isVpn = block == 1 || block == 2;
        VpnResult result = new VpnResult(isVpn, false, country, isp);
        cache.put(ip, result);
        return result;
    }

    private boolean isLocalIp(String ip) {
        return ip.startsWith("127.") || ip.startsWith("10.") ||
               ip.startsWith("192.168.") || ip.equals("0.0.0.0") ||
               ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
               ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
               ip.startsWith("172.2") || ip.startsWith("172.3") ||
               ip.equals("::1") || ip.equals("localhost");
    }

    public void clearCache() { cache.clear(); }
}
