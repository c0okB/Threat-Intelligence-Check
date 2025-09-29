import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public final class IPQualityScore {
    private static String API_KEY = "";
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 20_000;

    static {
        // 从 conf.ini 加载 IPQS_KEY
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream("conf.ini")) {
            props.load(fis);
            API_KEY = props.getProperty("IPQS_KEY", "");
            if (API_KEY == null || API_KEY.isEmpty()) {
                System.err.println("Warning: IPQS_KEY not found in conf.ini, IPQualityScore will be unable to call the API.");
            } else {
                System.out.println("IPQualityScore API Key loaded successfully");
            }
        } catch (Exception e) {
            System.err.println("Failed to read conf.ini (IPQualityScore): " + e.getMessage());
        }

        // 可选：启动时同步加载代理配置
        try { HttpProxyConfig.loadFromIniIfPresent("conf.ini"); } catch (Exception ignore) {}
    }

    private IPQualityScore() {}

    /**
     * 查询 IP 信誉（GET）
     * params:
     *  - strictness: 0/1/2 (官方建议范围)
     *  - allowPublicAccessPoints: 是否允许公共热点
     */
    public static String queryIp(String ip,
                                 String userAgent,
                                 int strictness,
                                 boolean allowPublicAccessPoints) {
        HttpURLConnection conn = null;
        try {
            if (API_KEY == null || API_KEY.isEmpty()) {
                return "Error: IPQS_KEY is empty";
            }
            if (ip == null || ip.isBlank()) {
                return "Error: ip is empty";
            }

            // 组装 URL 与查询参数
            String base = "https://ipqualityscore.com/api/json/ip/"
                    + URLEncoder.encode(API_KEY, StandardCharsets.UTF_8)
                    + "/" + URLEncoder.encode(ip.trim(), StandardCharsets.UTF_8);

            StringBuilder qs = new StringBuilder();
            qs.append("?strictness=").append(Math.max(0, strictness));
            qs.append("&allow_public_access_points=").append(allowPublicAccessPoints ? "true" : "false");
            if (userAgent != null && !userAgent.isBlank()) {
                qs.append("&user_agent=").append(URLEncoder.encode(userAgent, StandardCharsets.UTF_8));
            }

            URL url = new URL(base + qs);
            conn = HttpProxyConfig.open(url); // 经代理打开连接

            // 超时（在 HttpProxyConfig.open 里有全局默认的话，这里作为兜底/覆盖）
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            int code = conn.getResponseCode();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(
                    (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream(),
                    StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line; while ((line = in.readLine()) != null) sb.append(line);
                if (code < 200 || code >= 300) {
                    return "Error: HTTP " + code + " " + sb;
                }
                return sb.toString();
            }
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** 便捷重载：使用常见 UA、strictness=0、允许公共热点 */
    public static String queryIp(String ip) {
        String defaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                + "AppleWebKit/537.36 (KHTML, like Gecko) "
                + "Chrome/135.0.0.0 Safari/537.36";
        return queryIp(ip, defaultUA, 0, true);
    }

    /** 运行时刷新 API Key（与 Setting 面板联动） */
    public static void setApiKey(String key) {
        API_KEY = key == null ? "" : key.trim();
    }

    private static String asText(com.fasterxml.jackson.databind.JsonNode n) {
        return (n == null || n.isNull()) ? "null" : n.asText();
    }

}
