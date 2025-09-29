import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Properties;

public class VirusTotal {
    private static String VirusTotal_KEY;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(20);

    static {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream("conf.ini")) {
            props.load(fis);
            VirusTotal_KEY = props.getProperty("VT_KEY");
            if (VirusTotal_KEY == null || VirusTotal_KEY.isEmpty()) {
                System.err.println("Warning: VT_KEY not found in conf.ini, VirusTotal will be unable to call the API.");
            }else{
                System.out.println("VirusTotal API Key loaded successfully");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read conf.ini: " + e.getMessage(), e);
        }

        // Optional: Also load proxy from conf.ini at program startup (WorkFrame will also configure once at startup)
        HttpProxyConfig.loadFromIniIfPresent("conf.ini");
    }

    public static String getDomainReport(String domain) {
        try {
            HttpClient client = HttpProxyConfig.newHttpClient(); // ← Build HttpClient with proxy

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/domains/" + domain))
                    .timeout(REQUEST_TIMEOUT)
                    .header("accept", "application/json")
                    .header("x-apikey", VirusTotal_KEY)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200
                    ? response.body()
                    : "Error: HTTP " + response.statusCode() + "\n" + response.body();
        } catch (HttpTimeoutException te) {
            return "Error: request timeout (" + REQUEST_TIMEOUT.toSeconds() + "s)";
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        }
    }

    public static String getIpReport(String ip) {
        try {
            HttpClient client = HttpProxyConfig.newHttpClient(); // ← Build HttpClient with proxy

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/ip_addresses/" + ip))
                    .timeout(REQUEST_TIMEOUT)
                    .header("accept", "application/json")
                    .header("x-apikey", VirusTotal_KEY)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200
                    ? response.body()
                    : "Error: HTTP " + response.statusCode() + "\n" + response.body();
        } catch (HttpTimeoutException te) {
            return "Error: request timeout (" + REQUEST_TIMEOUT.toSeconds() + "s)";
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        }
    }

    /** Allow runtime refresh (optional) */
    public static void setApiKey(String key) {
        VirusTotal_KEY = key == null ? "" : key.trim();
    }
}
