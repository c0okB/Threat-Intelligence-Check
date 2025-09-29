import javax.swing.*;
import java.awt.*;

public class VirusTool {
    public static void main(String[] args) {
        HttpProxyConfig.enableProxyBasicAuthForJdk();
        SwingUtilities.invokeLater(() -> {
            // Global uncaught exception handler
            Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
                System.err.println("[GLOBAL] Uncaught on thread: " + t.getName());
                e.printStackTrace();
            });

            // EDT safety net
            Toolkit.getDefaultToolkit().getSystemEventQueue().push(new EventQueue() {
                @Override
                protected void dispatchEvent(AWTEvent event) {
                    try {
                        super.dispatchEvent(event);
                    } catch (Throwable ex) {
                        System.err.println("[EDT] Uncaught exception:");
                        ex.printStackTrace();
                    }
                }
            });

            WorkFrame f = new WorkFrame();
            f.setVisible(true);
        });
    }
}
