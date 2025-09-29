import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public class ThreatBook {
    // ===== 常量 & 状态 =====
    private static String API_KEY = "";
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 20_000;

    // ===== 静态初始化：读取 conf.ini，并初始化代理（与原逻辑一致）=====
    static {
        loadApiKeyFromIni("conf.ini");
        try {
            // 可选：启动时也尝试读取并应用代理配置（与原逻辑一致）
            HttpProxyConfig.loadFromIniIfPresent("conf.ini");
        } catch (Exception ignore) {}
    }

    /** DNS 场景查询（GET）——保持原方法签名与行为 */
    public static String QueryDNS(String domain) {
        HttpURLConnection connection = null;
        try {
            if (API_KEY == null || API_KEY.isEmpty()) {
                return "Error: ThreatBook API key is empty";
            }

            final String base = "https://api.threatbook.cn/v3/scene/dns";
            final String resource = normalizeResource(domain);
            final String params = buildQueryParams(API_KEY, resource);
            final URL url = new URL(base + "?" + params);

            // 使用代理打开连接（保留原调用）
            connection = HttpProxyConfig.open(url);

            // 统一设置更长的超时（不低于默认）
            connection.setConnectTimeout(Math.max(connection.getConnectTimeout(), CONNECT_TIMEOUT_MS));
            connection.setReadTimeout(Math.max(connection.getReadTimeout(), READ_TIMEOUT_MS));

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");

            final int responseCode = connection.getResponseCode();
            final String body = readBody(connection, responseCode);

            // 与原逻辑一致：非 2xx 直接包装错误串返回
            if (responseCode < 200 || responseCode >= 300) {
                return "Error: HTTP " + responseCode + " " + body;
            }
            return body;
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        } finally {
            if (connection != null) connection.disconnect(); // 保持及时释放连接
        }
    }

    /** IP 画像查询（GET */
    public static String AnalysisIP(String IP) {
        HttpURLConnection connection = null;
        try {
            if (API_KEY == null || API_KEY.isEmpty()) {
                return "Error: ThreatBook API key is empty";
            }

            final String base = "https://api.threatbook.cn/v3/ip/query";
            final String resource = normalizeResource(IP);
            final String params = buildQueryParams(API_KEY, resource);
            final URL url = new URL(base + "?" + params);

            // 使用代理打开连接（保持与 QueryDNS 一致）
            connection = HttpProxyConfig.open(url);

            // 统一设置超时（不低于默认）
            connection.setConnectTimeout(Math.max(connection.getConnectTimeout(), CONNECT_TIMEOUT_MS));
            connection.setReadTimeout(Math.max(connection.getReadTimeout(), READ_TIMEOUT_MS));

            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");

            final int responseCode = connection.getResponseCode();
            final String body = readBody(connection, responseCode);

            // 非 2xx 返回错误串
            if (responseCode < 200 || responseCode >= 300) {
                return "Error: HTTP " + responseCode + " " + body;
            }
            return body;
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /** 运行时刷新 API Key（与原逻辑一致） */
    public static void setApiKey(String key) {
        API_KEY = key == null ? "" : key.trim();
    }

    // =======================
    //        私有工具
    // =======================

    /** 从 conf.ini 读取 TB_KEY（保留原来副作用与日志输出） */
    private static void loadApiKeyFromIni(String iniPath) {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(iniPath)) {
            props.load(fis);
            API_KEY = props.getProperty("TB_KEY", "");
            if (API_KEY == null || API_KEY.isEmpty()) {
                System.err.println("Warning: TB_KEY not found in conf.ini, ThreatBook will be unable to call the API.");
            } else {
                System.out.println("ThreatBook API Key loaded successfully");
            }
        } catch (Exception e) {
            System.err.println("Failed to read conf.ini (ThreatBook): " + e.getMessage());
        }
    }

    /** 规范化 resource（去空白） */
    private static String normalizeResource(String domain) {
        return domain == null ? "" : domain.replaceAll("[\\s]+", "");
    }

    /** 构建查询参数并进行 URL 编码 */
    private static String buildQueryParams(String apiKey, String resource) throws Exception {
        String ak = URLEncoder.encode(apiKey, StandardCharsets.UTF_8.name());
        String rs = URLEncoder.encode(resource, StandardCharsets.UTF_8.name());
        return "apikey=" + ak + "&resource=" + rs;
    }

    /** 按响应码选择输入流并读取为字符串（UTF-8） */
    private static String readBody(HttpURLConnection connection, int responseCode) throws Exception {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                (responseCode >= 200 && responseCode < 300)
                        ? connection.getInputStream()
                        : connection.getErrorStream(),
                StandardCharsets.UTF_8))) {

            StringBuilder resp = new StringBuilder(2048);
            String line;
            while ((line = in.readLine()) != null) {
                resp.append(line);
            }
            return resp.toString();
        }
    }
}
