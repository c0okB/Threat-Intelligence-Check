import java.io.FileInputStream;
import java.io.IOException;
import java.net.*;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;
import java.util.Properties;

public final class HttpProxyConfig {
    /* ==============================
     * 1) 运行时状态（保持 volatile）
     * ============================== */
    private static volatile boolean enabled = false;
    private static volatile String host = "";
    private static volatile int port = 0;
    private static volatile String username = "";
    private static volatile char[] password = new char[0];

    /* ==============================
     * 2) 常量（超时配置，与原值一致）
     * ============================== */
    private static final int CONNECT_TIMEOUT_MS = 10_000;               // HttpURLConnection 连接超时
    private static final int READ_TIMEOUT_MS    = 20_000;               // HttpURLConnection 读取超时
    private static final Duration CLIENT_CONNECT_TIMEOUT = Duration.ofSeconds(10); // HttpClient 连接超时

    private HttpProxyConfig() {}

    /* ==============================
     * 3) JDK 代理认证能力开关（保持原方法名与行为）
     * ============================== */
    /** 允许对代理使用 Basic 认证（含 CONNECT 隧道） */
    public static void enableProxyBasicAuthForJdk() {
        System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
        System.setProperty("jdk.http.auth.proxying.disabledSchemes", "");
    }

    /* ==============================
     * 4) 从 ini 读取代理配置（可选调用）
     * ============================== */
    // === Helper to read conf.ini (optional) ===
    public static void loadFromIniIfPresent(String path) {
        try (FileInputStream in = new FileInputStream(path)) {
            Properties p = new Properties();
            p.load(in);

            boolean en = Boolean.parseBoolean(p.getProperty("PROXY_ENABLED", "false"));
            String  h  = p.getProperty("PROXY_HOST", "");
            int     po = parseIntSafe(p.getProperty("PROXY_PORT", "0"));
            String  u  = p.getProperty("PROXY_USER", "");
            String  pw = p.getProperty("PROXY_PASS", "");

            // 与原逻辑一致：传入 char[]，空则 new char[0]
            configure(en, h, po, u, pw == null ? new char[0] : pw.toCharArray());
        } catch (IOException ignore) {
            // 没有 ini 文件时静默忽略（保持原行为）
        }
    }

    private static int parseIntSafe(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return 0;
        }
    }

    /* ==============================
     * 5) 主配置入口（同步，保持原方法签名）
     * ============================== */
    // === Main configuration entry ===
    public static synchronized void configure(boolean en, String h, int po, String user, char[] pass) {
        enabled  = en;
        host     = h == null ? "" : h.trim();
        port     = po;
        username = user == null ? "" : user.trim();
        password = pass == null ? new char[0] : pass.clone();

        // 对 HttpURLConnection 生效：设置全局 Authenticator（仅在代理请求时返回凭据）
        if (enabled && !username.isEmpty()) {
            Authenticator.setDefault(buildProxyAuthenticator(username, password));
        }
        // 注：不主动清空已有默认 Authenticator，避免影响进程内其他组件（保持原注释语义）
    }

    private static Authenticator buildProxyAuthenticator(String user, char[] pass) {
        return new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                if (getRequestorType() == RequestorType.PROXY) {
                    return new PasswordAuthentication(user, pass);
                }
                return null;
            }
        };
    }

    /* ==============================
     * 6) 只读访问器（保持原方法名）
     * ============================== */
    public static boolean isEnabled() { return enabled; }
    public static String  getHost()   { return host;    }
    public static int     getPort()   { return port;    }
    public static String  getUsername(){ return username; }

    /* ==============================
     * 7) 代理对象/选择器构造
     * ============================== */
    private static ProxySelector toProxySelector() {
        return ProxySelector.of(new InetSocketAddress(host, port));
    }

    private static boolean proxyConfigured() {
        return enabled && host != null && !host.isEmpty() && port > 0;
    }

    /* ==============================
     * 8) HttpURLConnection 辅助：使用代理打开连接
     * ============================== */
    // === For HttpURLConnection: open a connection using proxy ===
    public static HttpURLConnection open(URL url) throws IOException {
        Objects.requireNonNull(url, "url");

        HttpURLConnection conn = (HttpURLConnection) (
                proxyConfigured()
                        ? url.openConnection(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port)))
                        : url.openConnection()
        );

        // 统一超时（保持与原逻辑一致）
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        return conn;
    }

    /* ==============================
     * 9) java.net.http.HttpClient 构造：带可选代理与认证
     * ============================== */
    // === For java.net.http.HttpClient: build a client that uses the proxy ===
    public static HttpClient newHttpClient() {
        HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(CLIENT_CONNECT_TIMEOUT);

        if (proxyConfigured()) {
            b.proxy(toProxySelector());
            if (!username.isEmpty()) {
                b.authenticator(buildProxyAuthenticator(username, password));
            }
        }
        return b.build();
    }
}
