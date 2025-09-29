import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.net.URLEncoder;

public class QianxinTIP {

    // ===== 常量与状态 =====
    private static String API_KEY = "";
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 20_000;
    private static final String INI_PATH        = "conf.ini";
    private static final String KEY_NAME        = "QAX_KEY";
    private static final String API_URL         = "https://ti.qianxin.com/api/v2/compromise";

    static {
        // 读取 API Key
        loadApiKeyFromIni(INI_PATH);

        // 启动时可选加载代理（与原逻辑一致）
        try {
            HttpProxyConfig.loadFromIniIfPresent(INI_PATH);
        } catch (Exception ignore) {}
    }

    /** Compromise detection query (POST) —— 保持原方法名与行为 */
    public static String SendVirusDetection(String param) {
        HttpURLConnection connection = null;
        try {
            if (API_KEY == null || API_KEY.isEmpty()) {
                return "Error: QAX_KEY is empty";
            }

            // 规范化输入
            final String researchString = normalizeParam(param);

            // 打开连接（走代理 & 统一超时兜底）
            connection = HttpProxyConfig.open(new URL(API_URL));
            connection.setConnectTimeout(Math.max(connection.getConnectTimeout(), CONNECT_TIMEOUT_MS));
            connection.setReadTimeout(Math.max(connection.getReadTimeout(), READ_TIMEOUT_MS));

            // POST 基本设置
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // 构造请求体并发送
            final byte[] payload = buildJsonPayload(API_KEY, researchString);
            connection.setFixedLengthStreamingMode(payload.length);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(payload);
            }

            // 读取响应
            final int code = connection.getResponseCode();
            final String body = readBody(connection, code);

            if (code < 200 || code >= 300) {
                return "Error: HTTP " + code + " " + body;
            }
            return body;

        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /** IP 信誉查询（GET）
     *  curl 'https://webapi.ti.qianxin.com/ip/v3/reputation?param=xxx'
     *   -H 'Api-Key: xxxxxxx'
     */
    public static String AnalysisIP(String ip) {
        HttpURLConnection connection = null;
        try {
            if (API_KEY == null || API_KEY.isEmpty()) {
                return "Error: QAX_KEY is empty";
            }

            // 规范化并 URL 编码查询参数
            final String resource = normalizeParam(ip);
            final String encodedParam = URLEncoder.encode(resource, StandardCharsets.UTF_8.name());
            final String urlStr = "https://webapi.ti.qianxin.com/ip/v3/reputation?param=" + encodedParam;

            // 打开连接（走代理）并做超时兜底
            connection = HttpProxyConfig.open(new URL(urlStr));
            connection.setConnectTimeout(Math.max(connection.getConnectTimeout(), CONNECT_TIMEOUT_MS));
            connection.setReadTimeout(Math.max(connection.getReadTimeout(), READ_TIMEOUT_MS));

            // GET + 头
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Api-Key", API_KEY);

            // 读取响应
            final int code = connection.getResponseCode();
            final String body = readBody(connection, code);

            if (code < 200 || code >= 300) {
                return "Error: HTTP " + code + " " + body;
            }
            return body;

        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /** URL/Domain 信誉检查（POST）
     *  POST https://a.ti.qianxin.com/url/v1/CheckUrls
     *  Headers:
     *    Api-Key: <API_KEY>
     *    Content-Type: application/json
     *  Body:
     *    {"queries":[{"index":0,"origin_url":"xxxxx"}]}
     */
    public static String AnalysisDomain(String domain) {
        HttpURLConnection connection = null;
        try {
            if (API_KEY == null || API_KEY.isEmpty()) {
                return "Error: QAX_KEY is empty";
            }

            java.net.URL url = new java.net.URL("https://a.ti.qianxin.com/url/v1/CheckUrls");
            connection = HttpProxyConfig.open(url); // 使用代理（全局已设默认超时，这里再兜底）
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);

            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Api-Key", API_KEY);
            connection.setDoOutput(true);

            String origin = (domain == null ? "" : domain).replaceAll("[\\s]+", "");
            String jsonInputString =
                    "{\"queries\":[{\"index\":0,\"origin_url\":\"" + origin + "\"}]}";

            byte[] payload = jsonInputString.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(payload.length);
            try (java.io.OutputStream os = connection.getOutputStream()) {
                os.write(payload);
            }

            int responseCode = connection.getResponseCode();
            try (java.io.BufferedReader in = new java.io.BufferedReader(
                    new java.io.InputStreamReader(
                            (responseCode >= 200 && responseCode < 300)
                                    ? connection.getInputStream()
                                    : connection.getErrorStream(),
                            java.nio.charset.StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String line; while ((line = in.readLine()) != null) response.append(line);
                if (responseCode < 200 || responseCode >= 300) {
                    return "Error: HTTP " + responseCode + " " + response;
                }
                return response.toString();
            }
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /** 运行时刷新（保持原方法名与语义） */
    public static void setApiKey(String key) {
        API_KEY = key == null ? "" : key.trim();
    }

    // =======================
    //        私有工具
    // =======================

    private static void loadApiKeyFromIni(String iniPath) {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(iniPath)) {
            props.load(fis);
            API_KEY = props.getProperty(KEY_NAME, "");
            if (API_KEY == null || API_KEY.isEmpty()) {
                System.err.println("Warning: " + KEY_NAME + " not found in conf.ini, QianxinTIP will be unable to call the API.");
            } else {
                System.out.println("QianxinTIP API Key loaded successfully");
            }
        } catch (IOException e) {
            System.err.println("Failed to read conf.ini (QianxinTIP): " + e.getMessage());
        }
    }

    /** 去掉所有空白字符，保持你原本的输入清洗逻辑 */
    private static String normalizeParam(String src) {
        return (src == null ? "" : src).replaceAll("[\\s]+", "");
    }

    /** 构造与原先等价的 JSON 请求体 */
    private static byte[] buildJsonPayload(String apiKey, String param) {
        String json =
                "{\"ignore_top\":true," +
                        "\"ignore_url\":true," +
                        "\"apikey\":\"" + apiKey + "\"," +
                        "\"param\":\"" + param + "\"," +
                        "\"ignore_port\":true}";
        return json.getBytes(StandardCharsets.UTF_8);
    }

    /** 根据响应码选择输入流并读取为 UTF-8 字符串 */
    private static String readBody(HttpURLConnection conn, int responseCode) throws IOException {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                (responseCode >= 200 && responseCode < 300)
                        ? conn.getInputStream()
                        : conn.getErrorStream(),
                StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder(2048);
            String line;
            while ((line = in.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }
}
