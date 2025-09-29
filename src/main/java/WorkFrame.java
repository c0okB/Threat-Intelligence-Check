import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.stream.Collectors;
import java.util.regex.Pattern;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import com.formdev.flatlaf.FlatClientProperties;

import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.extras.FlatInspector;

public class WorkFrame extends JFrame {
    /* ==============================
     * 1) 常量（配色/路径/键名/正则）
     * ============================== */

    // —— 徽章配色（柔和绿 / 柔和红）——
    private static final Color GOOD_FILL = new Color(0xE8F5E9);
    private static final Color GOOD_LINE = new Color(0xC8E6C9);
    private static final Color GOOD_FG = new Color(0x1B5E20);

    private static final Color BAD_FILL = new Color(0xFFEBEE);
    private static final Color BAD_LINE = new Color(0xFFCDD2);
    private static final Color BAD_FG = new Color(0xB71C1C);

    // ======= Configuration file =======
    private static final String CONF_PATH = "conf.ini";
    private static final String KEY_QAX = "QAX_KEY";
    private static final String KEY_VT = "VT_KEY";
    private static final String KEY_TB = "TB_KEY";
    private static final String KEY_IPQS = "IPQS_KEY";

    // ======= History =======
    private static final String HISTORY_PATH = "history.json";

    // HTTP Proxy keys
    private static final String KEY_PROXY_ENABLED = "PROXY_ENABLED";
    private static final String KEY_PROXY_HOST = "PROXY_HOST";
    private static final String KEY_PROXY_PORT = "PROXY_PORT";
    private static final String KEY_PROXY_USER = "PROXY_USER";
    private static final String KEY_PROXY_PASS = "PROXY_PASS";

    // IPv4/6 regex (simple)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|[0-1]?\\d{1,2})\\.){3}(25[0-5]|2[0-4]\\d|[0-1]?\\d{1,2})$");
    private static final Pattern IPV6_PATTERN = Pattern.compile("^[0-9a-fA-F:]+$");

    /* ==============================
     * 2) 全局状态（与数据缓存）
     * ============================== */

    // ======= History =======
    private JTable historyTable;
    private DefaultTableModel historyModel;
    private JButton histReloadBtn, histDeleteBtn, histClearBtn, histOpenBtn;
    private java.util.List<String> historyRawLines = new ArrayList<>();

    // 记录当前一次检索关键信息，供写入 history.json
    private String lastQueryRaw = "";
    private String lastQueryType = "UNKNOWN";

    // Provider responses
    private Analyzer.QAXResponseData qaxResp;
    private Analyzer.VirusTotalResponse vtResp;
    private Analyzer.ThreatBookResponse tbResp;

    /* ==============================
     * 3) UI 组件（按页面分组）
     * ============================== */

    // Tabs
    private JTabbedPane tabbedPane;

    // Status bar
    private final JLabel statusLabel = new JLabel(" Ready");
    private final JProgressBar progress = new JProgressBar();

    // Search page
    private final JTextField inputParam = new JTextField(26);
    private final JButton startSearchBtn = new JButton("Search");
    private final JButton deepAnalysisBtn = new JButton("DeepAnalysis");
    private final JButton clearBtn = new JButton("Clear");

    // 顶部徽章
    private JLabel vtRiskBadge;
    private JLabel qaxTotalBadge;
    private JLabel TBRiskBadge;

    // QAX
    private JTable qaxTable;
    private DefaultTableModel qaxTableModel;
    private JLabel qaxStatsLabel;

    // VT
    private JTable vtTable;
    private DefaultTableModel vtModel;
    private JLabel vtStatsLabel;

    // TB
    private JTable tbTable;
    private DefaultTableModel tbDomainModel;
    private DefaultTableModel tbIpModel;
    private JLabel tbStatsLabel;

    private JScrollPane qaxScrollOnIndex;
    private JScrollPane vtScrollOnIndex;
    private JScrollPane tbScrollOnIndex;

    // Setting panel (API Key)
    private JPasswordField qaxKeyField;
    private JPasswordField vtKeyField;
    private JPasswordField tbKeyField;
    private JCheckBox qaxShow;
    private JCheckBox vtShow;
    private JCheckBox tbShow;
    private JButton btnSaveConf;
    private JButton btnReloadConf;

    // Setting panel (IPQS)
    private JPasswordField ipqsKeyField;
    private JCheckBox ipqsShow;

    // Setting panel (HTTP Proxy)
    private JCheckBox proxyEnable;
    private JTextField proxyHost;
    private JTextField proxyPort;
    private JTextField proxyUser;
    private JPasswordField proxyPass;
    private JCheckBox proxyShow;
    private JLabel proxyStateLabel;

    // ===== IPQualityScore tab =====
    private JTextField ipqsInput = new JTextField(26);
    private JButton ipqsSearchBtn = new JButton("Search");
    private JButton ipqsClearBtn = new JButton("Clear");
    private JLabel ipqsStats;
    private PillLabel ipqsProxyBadge, ipqsVpnBadge, ipqsTorBadge, ipqsBotBadge;
    private JLabel ipqsIspValue, ipqsHostValue, ipqsGeoValue;

    // ==== Analysis tab =========
    private JTextArea analysisOutput;

    private JPanel analysisPanel; // 整个 Analysis 面板根容器
    // Analysis：分组容器引用（用于显隐）
    private JPanel ipGroupContainer;      // 包含 IP 的 Geo / WHOIS / Summary / Network
    private JPanel domainGroupContainer;  // 包含 Domain 的 Geo / Org / Timeline

    // 值标签（只展示，不可编辑）
    private JLabel aCity, aCountry, aProvince, aDistrict, aContinent;
    private JLabel aCidr, aWhoisServer, aMaliciousLabel, aIpserviceBenignLabel, aIpserviceUnknownLabel, aIpInfraLabel;
    private JLabel aOwner, aAsn, aAsnOrg, aRir, aOrganization, aRegdate, aRef, aUpdated;

    // —— QAX_Domain_Analysis 值标签 —— //
    private JLabel dOnlineStatus, dCity2, dContinentCode, dCountryCode, dContry;
    private JLabel dIspDomain, dOwner2, dRegion, dCreateTime, dUpdateTime;
    private JLabel dFirstDetectTime, dLastUpdateTime;

    /* ==============================
     * 4) 构造函数：只“导演”
     * ============================== */
    public WorkFrame() {
        setTitle("VirusCheckTool V0.2");
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        setSize(1280, 820);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(0, 0));

        initializeLookAndFeel();   // LAF & 全局 UI 属性
        initializeFields();        // 字段与基础组件
        initializeLayout();        // Header / Tabs / StatusBar
        initializeBindings();      // 事件绑定
        initializeStartupState();  // 启动加载配置与历史
    }

    /* ==============================
     * 5) 初始化阶段（分步骤，不改功能）
     * ============================== */

    private void initializeLookAndFeel() {
        Image icon = safeLoadAppIcon();
        if (icon != null) setIconImage(icon);

        FlatLightLaf.setup();
        UIManager.put("TabbedPane.tabAlignment", "leading");
        FlatInspector.install("ctrl shift alt X");

        UIManager.put("Component.arc", 16);
        UIManager.put("TextComponent.arc", 14);
        UIManager.put("Component.focusWidth", 1);
        UIManager.put("Component.innerFocusWidth", 0);

        UIManager.put("ScrollBar.thumbArc", 16);
        UIManager.put("ScrollBar.trackArc", 16);
        UIManager.put("ScrollBar.thumbInsets", new Insets(2, 2, 2, 2));
        UIManager.put("ScrollBar.showButtons", false);
        UIManager.put("Table.showHorizontalLines", Boolean.TRUE);
        UIManager.put("Table.showVerticalLines", Boolean.FALSE);
    }

    private void initializeFields() {
        qaxTotalBadge = new PillLabel("Total", svg("/icons/qax.svg", 20, 20));
        vtRiskBadge   = new PillLabel("Score", svg("/icons/vt.svg", 20, 20));
        TBRiskBadge   = new PillLabel("Risk",  svg("/icons/book.svg", 20, 20));
        for (JLabel b : new JLabel[]{ qaxTotalBadge, vtRiskBadge, TBRiskBadge }) {
            b.setFont(b.getFont().deriveFont(Font.BOLD, 14f));
            b.setBorder(BorderFactory.createEmptyBorder(6, 14, 6, 14));
            b.setIconTextGap(8);
        }

        qaxStatsLabel = new JLabel("QAX — —");
        vtStatsLabel  = new JLabel("VirusTotal — —");
        tbStatsLabel  = new JLabel("ThreatBook — —");

        initTablesForIndex();
    }


    private void initializeLayout() {
        add(buildHeader(), BorderLayout.NORTH);

        tabbedPane = new JTabbedPane();
        tabbedPane.putClientProperty("JTabbedPane.tabAlignment", "leading");
        tabbedPane.setComponentOrientation(ComponentOrientation.LEFT_TO_RIGHT);

        JPanel panelIndex = buildSearchCard();
        JPanel panelSetting = buildSettingCard();
        JPanel panelIPQS = buildIPQSTab();
        JPanel panelHistory = buildHistoryCard();
        JPanel panelAnalysis = buildAnalysisTab();

        tabbedPane.addTab("Search Board", svg("/icons/search.svg", 16, 16), panelIndex);
        tabbedPane.addTab("Analysis",       svg("/icons/Analysis.svg",   16, 16), panelAnalysis);
        tabbedPane.addTab("IPQualityScore", svg("/icons/ipqs.svg", 16, 16), panelIPQS);
        tabbedPane.addTab("History", svg("/icons/History.svg", 16, 16), panelHistory);
        tabbedPane.addTab("Setting", svg("/icons/Setting.svg", 16, 16), panelSetting);
        add(tabbedPane, BorderLayout.CENTER);

        JPanel statusBar = new JPanel(new BorderLayout());
        statusLabel.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        progress.setVisible(false);
        statusBar.add(statusLabel, BorderLayout.WEST);
        statusBar.add(progress, BorderLayout.EAST);
        add(statusBar, BorderLayout.SOUTH);
    }

    private void initializeBindings() {
        styleSearchBar(inputParam, "IPv4 / IPv6 / URL / Domain", startSearchBtn, clearBtn);
        //Search Button
        startSearchBtn.addActionListener(e -> triggerSearchBoth());

        // DeepAnalysis Button
        deepAnalysisBtn.putClientProperty(FlatClientProperties.BUTTON_TYPE, "roundRect");
        deepAnalysisBtn.putClientProperty(FlatClientProperties.STYLE, "arc:999; focusWidth:1; borderWidth:1;");
        deepAnalysisBtn.setMargin(new Insets(6, 12, 6, 12));

        // 点击 DeepAnalysis：校验 → Analysis 面板显示“Querying…” → 异步调用 ThreatBook.AnalysisIP → 输出结果 → 切换到 Analysis
        deepAnalysisBtn.addActionListener(e -> {
            final String raw = (inputParam.getText() == null) ? "" : inputParam.getText().trim();
            if (raw.isEmpty()) {
                warn("Please enter IP / domain / URL");
                inputParam.requestFocus();
                return;
            }

            clearQaxIpAnalysisBlock();
            clearQaxDomainAnalysisBlock();
            switchToAnalysisTab();                 // 跳到 Analysis 标签
            runDeepAnalysis(raw);                  // 异步请求并更新输出
        });


        inputParam.addActionListener(e -> triggerSearchBoth());
        clearBtn.addActionListener(e -> clearAllViews());
        startSearchBtn.setMnemonic(KeyEvent.VK_S);

        styleSearchBar(ipqsInput, "IP address", ipqsSearchBtn, ipqsClearBtn);
        ipqsSearchBtn.addActionListener(e -> triggerIPQSSearch());
        ipqsInput.addActionListener(e -> triggerIPQSSearch());
        ipqsClearBtn.addActionListener(e -> clearIPQSPanel());
    }

    private void initializeStartupState() {
        loadHistoryIntoTable();
        if (Files.exists(Paths.get(CONF_PATH))) {
            loadApiKeysFromFile();
        } else {
            ensureConfFileExists();
            SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(this,
                            "API Key Not Configured\nPlease go to the Setting panel to fill in and save.\n",
                            "API Key Not Configured", JOptionPane.WARNING_MESSAGE)
            );
        }
    }


    // ===== Header =====
    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBorder(BorderFactory.createEmptyBorder(12, 16, 8, 16));

        JLabel title = new JLabel("Hunt Threat");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 22f));

        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.add(title);
        left.add(Box.createVerticalStrut(4));


        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        JButton about = new JButton("About", svg("/icons/info.svg", 16, 16));
        about.addActionListener(e -> JOptionPane.showMessageDialog(this,
                "VirusCheckTool V0.2\n",
                "About", JOptionPane.INFORMATION_MESSAGE));
        bar.add(about);

        header.add(left, BorderLayout.WEST);
        header.add(bar, BorderLayout.EAST);
        return header;
    }

    // 小工具：为单个表格构造“标题 + 状态栏 + 表格”的容器
    private JPanel buildTablePanel(String title, JScrollPane scrollPane, JLabel statsLabel) {
        RoundedPanel panel = new RoundedPanel(16);
        panel.setLayout(new BorderLayout(8, 8));

        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        header.add(titleLabel, BorderLayout.WEST);

        if (scrollPane != null) {
            scrollPane.setBorder(BorderFactory.createEmptyBorder());
            if (scrollPane.getViewport() != null) scrollPane.getViewport().setOpaque(false);
            scrollPane.setOpaque(false);
        }

        panel.add(header, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        if (statsLabel != null) {
            JPanel footer = new JPanel(new BorderLayout());
            footer.setOpaque(false);
            statsLabel.setForeground(new Color(0x666666));
            statsLabel.setFont(statsLabel.getFont().deriveFont(12f));
            footer.add(statsLabel, BorderLayout.EAST);
            footer.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
            panel.add(footer, BorderLayout.SOUTH);
        }
        return panel;
    }

    // —— 胶囊徽章 —— //
    private static class PillLabel extends JLabel {
        private Color fill = new Color(0xEEF1F5);
        private Color line = new Color(0xD0D7DE);
        private Insets pad = new Insets(4, 10, 4, 10);

        PillLabel(String text, Icon icon) {
            super(text, icon, SwingConstants.LEADING);
            setOpaque(false);
            setBorder(BorderFactory.createEmptyBorder(pad.top, pad.left, pad.bottom, pad.right));
            setIconTextGap(6);
            setFont(getFont().deriveFont(Font.BOLD, 12f));
        }

        public void setFill(Color c) {
            fill = c;
            repaint();
        }

        public void setLine(Color c) {
            line = c;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();
            int arc = h;
            g2.setColor(fill);
            g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc);
            g2.setColor(new Color(0, 0, 0, 22));
            g2.drawRoundRect(0, 1, w - 1, h - 2, arc, arc);
            g2.setColor(line);
            g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    // ===== Search panel (composite view with 3 tables) =====
    private JPanel buildSearchCard() {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        toolbar.setOpaque(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        styleSearchBar(inputParam, "IPv4 / IPv6 / URL / Domain", startSearchBtn, clearBtn);


        startSearchBtn.setMnemonic(KeyEvent.VK_S);
        toolbar.add(new JLabel(" Search: "));
        toolbar.add(inputParam);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(startSearchBtn);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(deepAnalysisBtn); // ← 新增：放在中间
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(clearBtn);

        JPanel topWrap = new JPanel(new BorderLayout());
        topWrap.setOpaque(false);
        topWrap.setBorder(BorderFactory.createEmptyBorder(2, 0, 16, 0));

        JPanel badgesRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 16, 0));
        badgesRow.setOpaque(false);
        badgesRow.add(qaxTotalBadge);
        badgesRow.add(vtRiskBadge);
        badgesRow.add(TBRiskBadge);

        JPanel searchRow = new JPanel();
        searchRow.setOpaque(false);
        searchRow.setLayout(new BoxLayout(searchRow, BoxLayout.X_AXIS));
        toolbar.setAlignmentY(Component.CENTER_ALIGNMENT);
        badgesRow.setAlignmentY(Component.CENTER_ALIGNMENT);
        searchRow.add(toolbar);
        searchRow.add(Box.createHorizontalGlue());
        searchRow.add(badgesRow);
        searchRow.add(Box.createHorizontalGlue());
        topWrap.add(searchRow, BorderLayout.CENTER);
        topWrap.add(new JSeparator(), BorderLayout.SOUTH);

        card.add(topWrap, BorderLayout.NORTH);

        qaxStatsLabel = new JLabel("QAX — —");
        vtStatsLabel = new JLabel("VirusTotal — —");
        tbStatsLabel = new JLabel("ThreatBook — —");

        JPanel qaxPanel = buildTablePanel("QAX TIP Results", qaxScrollOnIndex, qaxStatsLabel);
        JPanel vtPanel = buildTablePanel("VirusTotal Results", vtScrollOnIndex, vtStatsLabel);
        JPanel tbPanel = buildTablePanel("ThreatBook Results", tbScrollOnIndex, tbStatsLabel);

        JSplitPane left = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, qaxPanel, vtPanel);
        left.setResizeWeight(0.34);
        left.setContinuousLayout(true);

        JSplitPane main = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, tbPanel);
        main.setResizeWeight(0.66);
        main.setContinuousLayout(true);

        qaxPanel.setMinimumSize(new Dimension(280, 200));
        vtPanel.setMinimumSize(new Dimension(280, 200));
        tbPanel.setMinimumSize(new Dimension(280, 200));

        card.add(main, BorderLayout.CENTER);
        return card;
    }

    // 初始化并装饰三张表（供 Search Board 复用）
    private void initTablesForIndex() {
        // QAX table
        String[] cols = {"risk", "alert_name", "ioc_category"};
        qaxTableModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        qaxTable = new JTable(qaxTableModel);
        stylizeTable(qaxTable);
        qaxTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        qaxTable.getTableHeader().setResizingAllowed(false);
        qaxTable.setShowVerticalLines(true);
        qaxTable.setGridColor(new Color(0xDADADA));
        installQaxRiskHighlighter();
        qaxScrollOnIndex = new JScrollPane(qaxTable);
        enableCellTooltips(qaxTable);

        // VT table
        String[] engineCols = {"engine_name", "result", "category"};
        vtModel = new DefaultTableModel(engineCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        vtTable = new JTable(vtModel);
        stylizeTable(vtTable);
        vtTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        vtTable.getTableHeader().setResizingAllowed(false);
        installVtResultHighlighter();
        vtScrollOnIndex = new JScrollPane(vtTable);
        enableCellTooltips(vtTable);

        // TB tables
        String[] domainCols = {"domain", "severity", "is_malicious"};
        tbDomainModel = new DefaultTableModel(domainCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        String[] ipCols = {"ip", "severity", "is_malicious"};
        tbIpModel = new DefaultTableModel(ipCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        tbTable = new JTable(tbDomainModel);   // default domain model
        stylizeTable(tbTable);
        tbTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        tbTable.getTableHeader().setResizingAllowed(false);
        installTbResultHighlighter();
        tbScrollOnIndex = new JScrollPane(tbTable);
        enableCellTooltips(tbTable);
    }

    // ===== Setting panel (API Key + HTTP Proxy + Real-time status) =====
    private JPanel buildSettingCard() {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0xCCCCCC), 1, true),
                BorderFactory.createEmptyBorder(16, 16, 16, 16)
        ));

        // --- API Key ---
        qaxKeyField = new JPasswordField(32);
        vtKeyField = new JPasswordField(32);
        tbKeyField = new JPasswordField(32);
        ipqsKeyField = new JPasswordField(32);

        qaxKeyField.setEchoChar('•');
        vtKeyField.setEchoChar('•');
        tbKeyField.setEchoChar('•');
        ipqsKeyField.setEchoChar('•');

        qaxKeyField.putClientProperty("JTextField.placeholderText", "QAX_TIP API Key");
        vtKeyField.putClientProperty("JTextField.placeholderText", "VirusTotal API Key");
        tbKeyField.putClientProperty("JTextField.placeholderText", "ThreatBook API Key");
        ipqsKeyField.putClientProperty("JTextField.placeholderText", "IPQualityScore API Key");

        qaxShow = new JCheckBox("Show");
        vtShow = new JCheckBox("Show");
        tbShow = new JCheckBox("Show");
        ipqsShow = new JCheckBox("Show");

        qaxShow.addActionListener(e -> togglePWVisibility(qaxKeyField, qaxShow.isSelected()));
        vtShow.addActionListener(e -> togglePWVisibility(vtKeyField, vtShow.isSelected()));
        tbShow.addActionListener(e -> togglePWVisibility(tbKeyField, tbShow.isSelected()));
        ipqsShow.addActionListener(e -> togglePWVisibility(ipqsKeyField, ipqsShow.isSelected()));

        btnSaveConf = new JButton("Save");
        btnReloadConf = new JButton("Reload");
        btnSaveConf.addActionListener(e -> saveApiKeysToFile());
        btnReloadConf.addActionListener(e -> loadApiKeysFromFile());

        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(6, 8, 6, 8);

        // Row 0: QAX Key
        gc.gridx = 0;
        gc.gridy = 0;
        gc.anchor = GridBagConstraints.EAST;
        form.add(new JLabel("QAX_TIP API Key:"), gc);
        gc.gridx = 1;
        gc.gridy = 0;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(qaxKeyField, gc);
        gc.gridx = 2;
        gc.gridy = 0;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.WEST;
        form.add(qaxShow, gc);

        // Row 1: VT Key
        gc.gridx = 0;
        gc.gridy = 1;
        gc.anchor = GridBagConstraints.EAST;
        form.add(new JLabel("VirusTotal API Key:"), gc);
        gc.gridx = 1;
        gc.gridy = 1;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(vtKeyField, gc);
        gc.gridx = 2;
        gc.gridy = 1;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.WEST;
        form.add(vtShow, gc);

        // Row 2: TB Key
        gc.gridx = 0;
        gc.gridy = 2;
        gc.anchor = GridBagConstraints.EAST;
        form.add(new JLabel("ThreatBook API Key:"), gc);
        gc.gridx = 1;
        gc.gridy = 2;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(tbKeyField, gc);
        gc.gridx = 2;
        gc.gridy = 2;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.WEST;
        form.add(tbShow, gc);

        // Row 3: IPQS Key
        gc.gridx = 0;
        gc.gridy = 3;
        gc.anchor = GridBagConstraints.EAST;
        form.add(new JLabel("IPQS API Key:"), gc);
        gc.gridx = 1;
        gc.gridy = 3;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(ipqsKeyField, gc);
        gc.gridx = 2;
        gc.gridy = 3;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.WEST;
        form.add(ipqsShow, gc);

        // --- HTTP Proxy group ---
        proxyEnable = new JCheckBox("Enable HTTP Proxy");
        proxyHost = new JTextField(18);
        proxyPort = new JTextField(6);
        proxyUser = new JTextField(12);
        proxyPass = new JPasswordField(12);
        proxyPass.setEchoChar('•');
        proxyShow = new JCheckBox("Show");
        proxyShow.addActionListener(e -> proxyPass.setEchoChar(proxyShow.isSelected() ? (char) 0 : '•'));

        // Row 4: Enable proxy
        gc.gridx = 0;
        gc.gridy = 4;
        gc.gridwidth = 3;
        gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.NONE;
        form.add(proxyEnable, gc);
        gc.gridwidth = 1;

        // Row 5: Host + Port
        gc.insets = new Insets(6, 8, 6, 8);
        gc.gridx = 0;
        gc.gridy = 5;
        gc.anchor = GridBagConstraints.EAST;
        form.add(new JLabel("Proxy Host:"), gc);
        gc.gridx = 1;
        gc.gridy = 5;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(proxyHost, gc);
        gc.gridx = 2;
        gc.gridy = 5;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.WEST;
        JPanel portPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        portPanel.add(new JLabel("Port:"));
        portPanel.add(proxyPort);
        form.add(portPanel, gc);

        // Row 6: User + Pass + Show
        gc.gridx = 0;
        gc.gridy = 6;
        gc.anchor = GridBagConstraints.EAST;
        form.add(new JLabel("Proxy User:"), gc);
        gc.gridx = 1;
        gc.gridy = 6;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        form.add(proxyUser, gc);
        gc.gridx = 2;
        gc.gridy = 6;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.WEST;
        JPanel passPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        passPanel.add(proxyPass);
        passPanel.add(proxyShow);
        form.add(passPanel, gc);

        // Real-time status label
        proxyStateLabel = new JLabel();
        proxyStateLabel.setBorder(BorderFactory.createEmptyBorder(8, 2, 0, 2));
        JPanel stateWrap = new JPanel(new BorderLayout());
        stateWrap.add(proxyStateLabel, BorderLayout.WEST);

        // Linkage: enable/disable input boxes and refresh status in real time
        proxyEnable.addActionListener(e -> {
            enableProxyInputs(proxyEnable.isSelected());
            updateProxyStatusLabel();
        });
        addDocChange(proxyHost, this::updateProxyStatusLabel);
        addDocChange(proxyPort, this::updateProxyStatusLabel);
        addDocChange(proxyUser, this::updateProxyStatusLabel);
        ipqsKeyField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { /* no-op */ }

            @Override
            public void removeUpdate(DocumentEvent e) { /* no-op */ }

            @Override
            public void changedUpdate(DocumentEvent e) { /* no-op */ }
        });
        proxyPass.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateProxyStatusLabel();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateProxyStatusLabel();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                updateProxyStatusLabel();
            }
        });

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actions.add(btnReloadConf);
        actions.add(btnSaveConf);

        card.add(new JLabel("Setting: Configure and save API Keys / HTTP Proxy (saved to ./conf.ini)"), BorderLayout.NORTH);
        card.add(form, BorderLayout.CENTER);
        card.add(stateWrap, BorderLayout.WEST);
        card.add(actions, BorderLayout.SOUTH);

        // Initial status
        enableProxyInputs(false);
        updateProxyStatusLabel();

        return card;
    }

    // Utility: add document listener to input fields
    private void addDocChange(JTextComponent c, Runnable r) {
        if (c == null || r == null) return;
        c.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                r.run();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                r.run();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                r.run();
            }
        });
    }

    private void togglePWVisibility(JPasswordField field, boolean visible) {
        if (visible) field.setEchoChar((char) 0);
        else field.setEchoChar('•');
    }

    /** Analysis 面板 */
    /** Analysis 面板（合并：QAX_Analysis = IP 分组 + Domain 分组） */
    private JPanel buildAnalysisTab() {
        analysisPanel = new JPanel(new BorderLayout());
        analysisPanel.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // ====== QAX_Analysis（单一区块，内部再分 IP/Domain 两组） ======
        JPanel qaxUnifiedBlock = new RoundedPanel(16);
        qaxUnifiedBlock.setLayout(new BorderLayout(8, 8));


        // 初始化 IP 值标签
        aCity = new JLabel();              aCountry = new JLabel();           aProvince = new JLabel();
        aDistrict = new JLabel();          aContinent = new JLabel();         aCidr = new JLabel();
        aWhoisServer = new JLabel();       aMaliciousLabel = new JLabel();    aIpserviceBenignLabel = new JLabel();
        aIpserviceUnknownLabel = new JLabel(); aIpInfraLabel = new JLabel();  aOwner = new JLabel();
        aAsn = new JLabel();               aAsnOrg = new JLabel();            aRir = new JLabel();
        aOrganization = new JLabel();      aRegdate = new JLabel();           aRef = new JLabel();
        aUpdated = new JLabel();

        JPanel ip_geo = createSection("IP · Geo", Arrays.asList(
                createKVCard("city", aCity),
                createKVCard("country", aCountry),
                createKVCard("province", aProvince),
                createKVCard("district", aDistrict),
                createKVCard("continent", aContinent)
        ));
        JPanel ip_whois = createSection("IP · WHOIS", Arrays.asList(
                createKVCard("cidr", aCidr),
                createKVCard("whois_server", aWhoisServer),
                createKVCard("rir", aRir),
                createKVCard("organization", aOrganization),
                createKVCard("regdate", aRegdate),
                createKVCard("ref", aRef),
                createKVCard("updated", aUpdated)
        ));
        JPanel ip_sum = createSection("IP · Summary", Arrays.asList(
                createKVCard("malicious_label", aMaliciousLabel),
                createKVCard("ipservice_benign_label", aIpserviceBenignLabel),
                createKVCard("ipservice_unknown_label", aIpserviceUnknownLabel),
                createKVCard("ip_infrastructure_label", aIpInfraLabel)
        ));
        JPanel ip_net = createSection("IP · Network", Arrays.asList(
                createKVCard("owner", aOwner),
                createKVCard("asn", aAsn),
                createKVCard("asn_org", aAsnOrg)
        ));

        ipGroupContainer = new JPanel();
        ipGroupContainer.setOpaque(false);
        ipGroupContainer.setLayout(new BoxLayout(ipGroupContainer, BoxLayout.Y_AXIS));
        for (JPanel sec : new JPanel[]{ip_geo, ip_whois, ip_sum, ip_net}) {
            sec.setAlignmentX(Component.LEFT_ALIGNMENT);
            ipGroupContainer.add(sec);
            ipGroupContainer.add(Box.createVerticalStrut(4)); // 原 12 → 4
        }

        // ---------- Domain 组（你的第二块字段） ----------
        // 初始化域名区块标签
        dOnlineStatus = new JLabel(); dCity2 = new JLabel(); dContinentCode = new JLabel();
        dCountryCode = new JLabel(); dContry = new JLabel(); dIspDomain = new JLabel();
        dOwner2 = new JLabel(); dRegion = new JLabel(); dCreateTime = new JLabel();
        dUpdateTime = new JLabel(); dFirstDetectTime = new JLabel(); dLastUpdateTime = new JLabel();

        JPanel d_geo = createSection("Domain · Geo", Arrays.asList(
                createKVCard("city", dCity2),
                createKVCard("continent_code", dContinentCode),
                createKVCard("country_code", dCountryCode),
                createKVCard("contry", dContry),
                createKVCard("region", dRegion)
        ));
        JPanel d_org = createSection("Domain · Org/ISP", Arrays.asList(
                createKVCard("owner", dOwner2),
                createKVCard("isp_domain", dIspDomain),
                createKVCard("online_status", dOnlineStatus)
        ));
        JPanel d_time = createSection("Domain · Timeline", Arrays.asList(
                createKVCard("create_time", dCreateTime),
                createKVCard("update_time", dUpdateTime),
                createKVCard("first_detect_time", dFirstDetectTime),
                createKVCard("last_update_time", dLastUpdateTime)
        ));

        domainGroupContainer = new JPanel();
        domainGroupContainer.setOpaque(false);
        domainGroupContainer.setLayout(new BoxLayout(domainGroupContainer, BoxLayout.Y_AXIS));
        for (JPanel sec : new JPanel[]{d_geo, d_org, d_time}) {
            sec.setAlignmentX(Component.LEFT_ALIGNMENT);
            domainGroupContainer.add(sec);
            domainGroupContainer.add(Box.createVerticalStrut(12));
        }

        // 中心滚动区：把两组依次堆叠（后续通过显隐切换）
        JPanel stack = new JPanel();
        stack.setOpaque(false);
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        ipGroupContainer.setAlignmentX(Component.LEFT_ALIGNMENT);
        domainGroupContainer.setAlignmentX(Component.LEFT_ALIGNMENT);
        stack.add(ipGroupContainer);
        stack.add(Box.createVerticalStrut(12));
        stack.add(domainGroupContainer);

        JScrollPane sp = new JScrollPane(stack);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getViewport().setOpaque(false);
        sp.setOpaque(false);
        qaxUnifiedBlock.add(sp, BorderLayout.CENTER);

        // 放到页面
        JPanel centerStack = new JPanel();
        centerStack.setOpaque(false);
        centerStack.setLayout(new BoxLayout(centerStack, BoxLayout.Y_AXIS));
        qaxUnifiedBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        centerStack.add(qaxUnifiedBlock);

        analysisPanel.add(centerStack, BorderLayout.CENTER);

        // 默认清空显示并先都隐藏（等到检索后由类型决定显隐）
        clearQaxIpAnalysisBlock();
        clearQaxDomainAnalysisBlock();
        setAnalysisMode(null); // 全部隐藏

        return analysisPanel;
    }

    /** 根据类型切换 Analysis 显示：IPv4/IPv6 显示 IP 组；DOMAIN 显示 Domain 组；null 全隐藏 */
    private void setAnalysisMode(String type) {
        boolean showIp = "IPv4".equals(type) || "IPv6".equals(type);
        boolean showDomain = "DOMAIN".equals(type);

        if (ipGroupContainer != null) ipGroupContainer.setVisible(showIp);
        if (domainGroupContainer != null) domainGroupContainer.setVisible(showDomain);

        if (analysisPanel != null) {
            analysisPanel.revalidate();
            analysisPanel.repaint();
        }
    }

    /** 清空并隐藏两组（用于开始检索前的空态） */
    private void resetAnalysisGroups() {
        clearQaxIpAnalysisBlock();
        clearQaxDomainAnalysisBlock();
        setAnalysisMode(null);
    }

    /** 小卡片：标题在上（灰色小字），值在下（加粗），圆角、轻边框，可自动换行 */
    private JPanel createKVCard(String title, JLabel valueLabel) {
        RoundedPanel card = new RoundedPanel(10);
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setOpaque(false);
        card.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6)); // 极小

        JLabel t = new JLabel(title);
        t.setForeground(new Color(0x6B7280));
        t.setFont(t.getFont().deriveFont(Font.PLAIN, 11f));

        valueLabel.setFont(valueLabel.getFont().deriveFont(Font.BOLD, 11f));
        String txt = valueLabel.getText();
        if (txt == null || txt.isEmpty()) txt = "—";
        valueLabel.setText("<html><div style='white-space:nowrap;margin:0;padding:0;line-height:1.15;'>" + txt + "</div></html>");

        card.add(t);
        card.add(Box.createVerticalStrut(2));
        card.add(valueLabel);

        // 让首选高度尽量小，并避免被父布局“放大”
        Dimension pref = card.getPreferredSize();
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, pref.height));
        return card;
    }


    /** 分组容器：顶部组标题，下方是流式卡片区（自动换行），整体放在圆角 Panel 里 */
    private JPanel createSection(String sectionTitle, java.util.List<JPanel> cards) {
        RoundedPanel section = new RoundedPanel(10);
        section.setLayout(new BorderLayout(4, 4));
        section.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6)); // 很小的上下左右

        JLabel h = new JLabel(sectionTitle);
        h.setFont(h.getFont().deriveFont(Font.BOLD, 12f));
        h.setBorder(BorderFactory.createEmptyBorder(0, 1, 0, 1));

        JPanel flow = new JPanel(new AutoWrapLayout(6, 4)); // 横 6、竖 4，很紧凑
        flow.setOpaque(false);
        for (JPanel c : cards) {
            // 关键：卡片按“首选尺寸”摆放，不设很大的 maxSize，避免被拉高
            c.setMaximumSize(c.getPreferredSize());
            flow.add(c);
        }

        section.add(h, BorderLayout.NORTH);
        section.add(flow, BorderLayout.CENTER);
        return section;
    }


    private void clearQaxIpAnalysisBlock() {
        for (JLabel l : new JLabel[]{
                aCity,aCountry,aProvince,aDistrict,aContinent,aCidr,aWhoisServer,
                aMaliciousLabel,aIpserviceBenignLabel,aIpserviceUnknownLabel,aIpInfraLabel,
                aOwner,aAsn,aAsnOrg,aRir,aOrganization,aRegdate,aRef,aUpdated
        }) {
            if (l != null) l.setText("—");
        }
    }

    private void clearQaxDomainAnalysisBlock() {
        for (JLabel l : new JLabel[]{
                dOnlineStatus, dCity2, dContinentCode, dCountryCode, dContry,
                dIspDomain, dOwner2, dRegion, dCreateTime, dUpdateTime,
                dFirstDetectTime, dLastUpdateTime
        }) {
            if (l != null) l.setText("—");
        }
    }

    /** 异步执行 QAX TIP 分析，并把结果写入 Analysis 面板（QAX_IP_Analysis 区块 + 原始JSON） */
    private void runDeepAnalysis(String info) {
        final String query = (info == null) ? "" : info.trim();
        setBusy(true, "Checking...");

        resetAnalysisGroups();

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                String type = detectType(query);
                // QAX TIP：IP 走 IP 信誉；非 IP（域名/URL）走 URL Check
                return ("IPv4".equals(type) || "IPv6".equals(type))
                        ? QianxinTIP.AnalysisIP(query)
                        : QianxinTIP.AnalysisDomain(query);
            }

            @Override
            protected void done() {
                try {
                    String resp = get();
                    System.out.println(resp);
                    if (resp == null) {
                        return;
                    }
                    String type = detectType(query);
                    setAnalysisMode(type);  // ← 先决定显示哪个分组

                    if ("IPv4".equals(type) || "IPv6".equals(type)) {
                        Analyzer.QAXIpReputationResponse obj =
                                Analyzer.QAX_AnalysisIP_ParseJson(resp);
                        fillQaxIpAnalysisBlockFromIp(obj, query);
                    } else {
                        Analyzer.QAXDomainCheckResponse obj =
                                Analyzer.QAX_AnalysisDomain_ParseJson(resp);
                        fillQaxDomainAnalysisBlockFromDomain(obj, query);
                    }
                } catch (Exception ex) {
                    // 出错时保持 IP 区块为空态
                    System.out.println("ERROR");
                    clearQaxIpAnalysisBlock();
                    clearQaxDomainAnalysisBlock();
                } finally {
                    setBusy(false, "Analysis completed");
                }
            }
        }.execute();
    }

    private void fillQaxIpAnalysisBlockFromIp(Analyzer.QAXIpReputationResponse r, String ipKey) {
        // 空/异常场景：清空块
        if (r == null || r.data == null || r.data.isEmpty()) {
            clearQaxIpAnalysisBlock();
            return;
        }

        // 取指定IP记录；若key不匹配，兜底取第一个
        Analyzer.QAXIpReputationResponse.IpRecord d = r.data.get(ipKey);
        if (d == null) {
            d = r.data.values().iterator().next();
        }
        if (d == null) {
            clearQaxIpAnalysisBlock();
            return;
        }

        // === GEO ===
        Analyzer.QAXIpReputationResponse.Geo g = d.geo;
        setTextOrDash(aCity,      g == null ? null : g.city);
        setTextOrDash(aCountry,   g == null ? null : g.country);
        setTextOrDash(aProvince,  g == null ? null : g.province);
        setTextOrDash(aDistrict,  g == null ? null : g.district);
        setTextOrDash(aContinent, g == null ? null : g.continent);

        // === WHOIS ===
        Analyzer.QAXIpReputationResponse.Whois w = d.whois;
        setTextOrDash(aCidr,        w == null ? null : joinList(w.cidr));
        setTextOrDash(aWhoisServer, w == null ? null : w.whoisServer);
        setTextOrDash(aRir,         w == null ? null : w.rir);
        setTextOrDash(aOrganization,w == null ? null : w.organization);
        setTextOrDash(aRegdate,     w == null ? null : w.regdate);
        setTextOrDash(aRef,         w == null ? null : w.ref);
        setTextOrDash(aUpdated,     w == null ? null : w.updated);

        // === Summary labels ===
        Analyzer.QAXIpReputationResponse.Summary s = d.summaryInfo;
        setTextOrDash(aMaliciousLabel,        s == null ? null : joinList(s.maliciousLabel));
        setTextOrDash(aIpserviceBenignLabel,  s == null ? null : joinList(s.ipserviceBenignLabel));
        setTextOrDash(aIpserviceUnknownLabel, s == null ? null : joinList(s.ipserviceUnknownLabel));
        setTextOrDash(aIpInfraLabel,          s == null ? null : joinList(s.ipInfrastructureLabel));

        // === Normal info ===
        Analyzer.QAXIpReputationResponse.NormalInfo ni = d.normalInfo;
        setTextOrDash(aOwner,  ni == null ? null : ni.owner);
        setTextOrDash(aAsn,    ni == null ? null : ni.asn);
        setTextOrDash(aAsnOrg, ni == null ? null : ni.asnOrg);
    }

    private void fillQaxDomainAnalysisBlockFromDomain(Analyzer.QAXDomainCheckResponse r, String domainKey) {
        // 异常/空数据：清空并返回
        if (r == null || r.replies == null || r.replies.isEmpty()) {
            clearQaxDomainAnalysisBlock();
            return;
        }

        // 选中最匹配当前查询域名的 reply；匹配不到就取第一个
        Analyzer.QAXDomainCheckResponse.Reply chosen = null;
        for (Analyzer.QAXDomainCheckResponse.Reply rep : r.replies) {
            if (rep == null) continue;
            String top = (rep.uss != null && rep.uss.uss != null) ? rep.uss.uss.top_domain : null;
            String url = (rep.uss != null && rep.uss.uss != null) ? rep.uss.uss.url : null;
            if (domainMatches(domainKey, top, url)) {
                chosen = rep;
                break;
            }
        }
        if (chosen == null) chosen = r.replies.get(0);
        if (chosen == null) {
            clearQaxDomainAnalysisBlock();
            return;
        }

        // 从 Meta.meta 读取地理/主体/时间
        Analyzer.QAXDomainCheckResponse.MetaInner m =
                (chosen.meta != null) ? chosen.meta.meta : null;

        // 从 UssSection.uss 读取 first_detect_time / last_update_time
        Analyzer.QAXDomainCheckResponse.Uss u =
                (chosen.uss != null) ? chosen.uss.uss : null;

        // —— 逐项填充（传 null 会显示为 "—"）——
        setTextOrDash(dOnlineStatus,     (m == null ? null : m.online_status));
        setTextOrDash(dCity2,            (m == null ? null : m.city));
        setTextOrDash(dContinentCode,    (m == null ? null : m.continent_code));
        setTextOrDash(dCountryCode,      (m == null ? null : m.country_code));
        setTextOrDash(dContry,           (m == null ? null : m.contry));          // 按服务端原拼写
        setTextOrDash(dIspDomain,        (m == null ? null : m.isp_domain));
        setTextOrDash(dOwner2,           (m == null ? null : m.owner));
        setTextOrDash(dRegion,           (m == null ? null : m.region));
        setTextOrDash(dCreateTime,       (m == null ? null : m.create_time));
        setTextOrDash(dUpdateTime,       (m == null ? null : m.update_time));
        setTextOrDash(dFirstDetectTime,  (u == null ? null : u.first_detect_time));
        setTextOrDash(dLastUpdateTime,   (u == null ? null : u.last_update_time));
    }

    /** 域名匹配：优先 top_domain 完整匹配；其次 url 包含；都不行则不匹配 */
    private boolean domainMatches(String key, String topDomain, String url) {
        if (key == null || key.isEmpty()) return false;
        String k = key.trim().toLowerCase(Locale.ROOT);
        if (topDomain != null && k.equals(topDomain.trim().toLowerCase(Locale.ROOT))) return true;
        if (url != null && url.toLowerCase(Locale.ROOT).contains(k)) return true;
        return false;
    }



    // 小工具：有值写值，没值写 "—"
    private void setTextOrDash(javax.swing.JLabel lbl, String val) {
        if (lbl == null) return;
        if (val == null || val.trim().isEmpty()) lbl.setText("—");
        else lbl.setText(val.trim());
    }



    /**
     * IPQualityScore 面板
     */
    private JPanel buildIPQSTab() {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // 顶部工具栏
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        toolbar.setOpaque(false);
        toolbar.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        // 与主搜索一致的样式
        styleSearchBar(ipqsInput, "IP address", ipqsSearchBtn, ipqsClearBtn);

        toolbar.add(new JLabel(" Search: "));
        toolbar.add(ipqsInput);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(ipqsSearchBtn);
        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(ipqsClearBtn);

        JPanel topWrap = new JPanel(new BorderLayout());
        topWrap.setOpaque(false);
        topWrap.setBorder(BorderFactory.createEmptyBorder(2, 0, 12, 0));
        topWrap.add(toolbar, BorderLayout.CENTER);

        // Proxy / VPN / Tor / Bot 徽章
        JPanel badgeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        badgeRow.setOpaque(false);
        ipqsProxyBadge = new PillLabel("Proxy —", svg("/icons/shield.svg", 16, 16));
        ipqsVpnBadge = new PillLabel("VPN —", svg("/icons/shield.svg", 16, 16));
        ipqsTorBadge = new PillLabel("Tor —", svg("/icons/shield.svg", 16, 16));
        ipqsBotBadge = new PillLabel("Bot —", svg("/icons/shield.svg", 16, 16));
        setBadgeNeutral(ipqsProxyBadge);
        setBadgeNeutral(ipqsVpnBadge);
        setBadgeNeutral(ipqsTorBadge);
        setBadgeNeutral(ipqsBotBadge);
        badgeRow.add(ipqsProxyBadge);
        badgeRow.add(ipqsVpnBadge);
        badgeRow.add(ipqsTorBadge);
        badgeRow.add(ipqsBotBadge);

        // ISP / HOST / GEO 信息
        JPanel info = new JPanel(new GridBagLayout());
        info.setOpaque(false);
        info.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0xDDDDDD), 1, true),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)
        ));
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(6, 8, 6, 8);
        gc.anchor = GridBagConstraints.EAST;

        ipqsIspValue = new JLabel("—");
        ipqsHostValue = new JLabel("—");
        ipqsGeoValue = new JLabel("—");

        gc.gridx = 0;
        gc.gridy = 0;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.EAST;
        info.add(new JLabel("ISP:"), gc);
        gc.gridx = 1;
        gc.gridy = 0;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.WEST;
        info.add(ipqsIspValue, gc);

        gc.gridx = 0;
        gc.gridy = 1;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.EAST;
        info.add(new JLabel("HOST:"), gc);
        gc.gridx = 1;
        gc.gridy = 1;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.WEST;
        info.add(ipqsHostValue, gc);

        gc.gridx = 0;
        gc.gridy = 2;
        gc.weightx = 0;
        gc.fill = GridBagConstraints.NONE;
        gc.anchor = GridBagConstraints.EAST;
        info.add(new JLabel("Geo:"), gc);
        gc.gridx = 1;
        gc.gridy = 2;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.WEST;
        info.add(ipqsGeoValue, gc);

        // === 把 badgeRow 和 info 放到同一个容器里（上下紧贴） ===
        JPanel stack = new JPanel();
        stack.setOpaque(false);
        stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
        badgeRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        info.setAlignmentX(Component.LEFT_ALIGNMENT);
        stack.add(badgeRow);
        stack.add(Box.createVerticalStrut(4));
        stack.add(info);

        // === 顶部列：topWrap + 分隔线 + stack ===
        JPanel northColumn = new JPanel();
        northColumn.setOpaque(false);
        northColumn.setLayout(new BoxLayout(northColumn, BoxLayout.Y_AXIS));
        topWrap.setAlignmentX(Component.LEFT_ALIGNMENT);
        stack.setAlignmentX(Component.LEFT_ALIGNMENT);
        topWrap.setMaximumSize(new Dimension(Integer.MAX_VALUE, topWrap.getPreferredSize().height));
        stack.setMaximumSize(new Dimension(Integer.MAX_VALUE, stack.getPreferredSize().height));
        topWrap.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
        JSeparator divider = new JSeparator(SwingConstants.HORIZONTAL);
        divider.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        northColumn.add(topWrap);
        northColumn.add(Box.createVerticalStrut(6));
        northColumn.add(divider);
        northColumn.add(Box.createVerticalStrut(6));
        northColumn.add(stack);

        // === 底部：状态摘要（右对齐） ===
        ipqsStats = new JLabel("—");
        JPanel footer = new JPanel(new BorderLayout());
        footer.setOpaque(false);
        footer.add(ipqsStats, BorderLayout.EAST);

        // 布局到卡片
        card.add(northColumn, BorderLayout.NORTH);
        card.add(footer, BorderLayout.SOUTH);

        return card;
    }

    /**
     * 清空 IPQS 面板
     */
    private void clearIPQSPanel() {
        if (ipqsInput != null) ipqsInput.setText("");
        if (ipqsStats != null) ipqsStats.setText("—");
        setIPQSAllNeutral();
        status("IPQS cleared");
    }

    /**
     * 触发 IPQS 查询（使用 Analyzer.IPQS_ParseJson 解析并更新徽章/信息区）
     */
    private void triggerIPQSSearch() {
        final String ip = (ipqsInput.getText() == null) ? "" : ipqsInput.getText().trim();
        if (ip.isEmpty()) {
            warn("Please enter an IP to query");
            ipqsInput.requestFocus();
            return;
        }

        ipqsSearchBtn.setEnabled(false);
        ipqsInput.setEnabled(false);
        ipqsClearBtn.setEnabled(false);

        setBusy(true, "IPQualityScore querying…");
        ipqsStats.setText("Querying…");
        setIPQSAllNeutral();

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return IPQualityScore.queryIp(ip);
            }

            @Override
            protected void done() {
                try {
                    String json = get();

                    if (json == null) {
                        ipqsStats.setText("Empty response");
                        return;
                    }
                    if (json.startsWith("Error:") || json.startsWith("Exception:")) {
                        ipqsStats.setText(json);
                        return;
                    }

                    Analyzer.IPQSResponse r = Analyzer.IPQS_ParseJson(json);
                    updateIPQSWidgets(r);

                    String summary = String.format(
                            "fraud_score=%d, proxy=%s, vpn=%s, tor=%s, bot=%s",
                            r.fraud_score, r.proxy, r.vpn, r.tor, r.bot_status
                    );
                    ipqsStats.setText(summary);

                } catch (Exception ex) {
                    ipqsStats.setText("IPQS parse failed: " + ex.getMessage());
                    status("IPQualityScore error: " + ex.getMessage());
                } finally {
                    setBusy(false, "IPQualityScore completed");
                    ipqsSearchBtn.setEnabled(true);
                    ipqsInput.setEnabled(true);
                    ipqsClearBtn.setEnabled(true);
                }
            }
        }.execute();
    }

    /**
     * 将 4 个布尔徽章和 3 个文本字段设置为中性
     */
    private void setIPQSAllNeutral() {
        setBadgeNeutral(ipqsProxyBadge);
        setBadgeNeutral(ipqsVpnBadge);
        setBadgeNeutral(ipqsTorBadge);
        setBadgeNeutral(ipqsBotBadge);
        ipqsIspValue.setText("—");
        ipqsHostValue.setText("—");
        ipqsGeoValue.setText("—");
    }

    /**
     * 根据布尔值更新徽章（true=红，false=绿）
     */
    private void setIPQSBoolBadge(PillLabel badge, String label, boolean value) {
        if (badge == null) return;
        badge.setText(label + (value ? ": Yes" : ": No"));
        setPillState(badge, !value); // true=bad(红)，false=good(绿)
    }

    /**
     * 设置徽章为中性“—”
     */
    private void setBadgeNeutral(PillLabel b) {
        if (b == null) return;
        b.setText(b.getText().split(":")[0] + " —");
        if (b instanceof PillLabel) {
            ((PillLabel) b).setFill(new Color(0xEEF1F5));
            ((PillLabel) b).setLine(new Color(0xD0D7DE));
        }
        b.setForeground(UIManager.getColor("Label.foreground"));
    }


    /**
     * 用解析结果回填到 UI
     */
    private void updateIPQSWidgets(Analyzer.IPQSResponse r) {
        if (r == null) {
            setIPQSAllNeutral();
            return;
        }

        setIPQSBoolBadge(ipqsProxyBadge, "Proxy", r.proxy);
        setIPQSBoolBadge(ipqsVpnBadge, "VPN", r.vpn);
        setIPQSBoolBadge(ipqsTorBadge, "Tor", r.tor);
        setIPQSBoolBadge(ipqsBotBadge, "Bot", r.bot_status);

        ipqsIspValue.setText((r.ISP == null || r.ISP.isEmpty()) ? "—" : r.ISP);
        ipqsHostValue.setText((r.host == null || r.host.isEmpty()) ? "—" : r.host);

        StringBuilder geo = new StringBuilder();
        if (r.country_code != null && !r.country_code.isEmpty()) geo.append(r.country_code);
        if (r.region != null && !r.region.isEmpty()) geo.append(geo.length() > 0 ? "/" : "").append(r.region);
        if (r.city != null && !r.city.isEmpty()) geo.append(geo.length() > 0 ? "/" : "").append(r.city);
        ipqsGeoValue.setText(geo.length() == 0 ? "—" : geo.toString());
    }

    // ===== Read/write conf.ini =====
    private void loadApiKeysFromFile() {
        try {
            File f = new File(CONF_PATH);
            if (!f.exists()) {
                status("conf.ini not found");
                return;
            }
            Properties p = new Properties();
            try (FileInputStream in = new FileInputStream(f)) {
                p.load(in);
            }
            // keys
            String qaxKey = p.getProperty(KEY_QAX, "");
            qaxKeyField.setText(qaxKey);
            QianxinTIP.setApiKey(qaxKey);

            String vtKey = p.getProperty(KEY_VT, "");
            vtKeyField.setText(vtKey);
            VirusTotal.setApiKey(vtKey);

            String tbKey = p.getProperty(KEY_TB, "");
            tbKeyField.setText(tbKey);
            ThreatBook.setApiKey(tbKey);

            String ipqsKey = p.getProperty(KEY_IPQS, "");
            ipqsKeyField.setText(ipqsKey);
            IPQualityScore.setApiKey(ipqsKey);

            // proxy
            boolean en = Boolean.parseBoolean(p.getProperty(KEY_PROXY_ENABLED, "false"));
            String h = p.getProperty(KEY_PROXY_HOST, "");
            String po = p.getProperty(KEY_PROXY_PORT, "0");
            String u = p.getProperty(KEY_PROXY_USER, "");
            String pw = p.getProperty(KEY_PROXY_PASS, "");

            proxyEnable.setSelected(en);
            proxyHost.setText(h);
            proxyPort.setText(po);
            proxyUser.setText(u);
            proxyPass.setText(pw);

            enableProxyInputs(en);
            applyProxyFromFields();
            updateProxyStatusLabel();

            status("Configuration loaded from conf.ini");
            JOptionPane.showMessageDialog(this, "Configuration loaded", "Setting", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            ex.printStackTrace();
            error("Failed to read configuration: " + ex.getMessage());
        }
    }

    private void saveApiKeysToFile() {
        try {
            Properties p = new Properties();
            // api keys
            String qax = new String(qaxKeyField.getPassword()).trim();
            String vt = new String(vtKeyField.getPassword()).trim();
            String tb = new String(tbKeyField.getPassword()).trim();
            String ipqs = new String(ipqsKeyField.getPassword()).trim();

            p.setProperty(KEY_QAX, qax);
            QianxinTIP.setApiKey(qax);

            p.setProperty(KEY_VT, vt);
            VirusTotal.setApiKey(vt);

            p.setProperty(KEY_TB, tb);
            ThreatBook.setApiKey(tb);

            p.setProperty(KEY_IPQS, ipqs);
            IPQualityScore.setApiKey(ipqs);

            // proxy
            p.setProperty(KEY_PROXY_ENABLED, String.valueOf(proxyEnable.isSelected()));
            p.setProperty(KEY_PROXY_HOST, proxyHost.getText() == null ? "" : proxyHost.getText().trim());
            p.setProperty(KEY_PROXY_PORT, proxyPort.getText() == null ? "" : proxyPort.getText().trim());
            p.setProperty(KEY_PROXY_USER, proxyUser.getText() == null ? "" : proxyUser.getText().trim());
            p.setProperty(KEY_PROXY_PASS, new String(proxyPass.getPassword()));

            try (FileOutputStream out = new FileOutputStream(CONF_PATH)) {
                p.store(out, "VirusTool API Keys (QAX/VT/TB/IPQS) & HTTP Proxy");
                QianxinTIP.setApiKey(qax);
                VirusTotal.setApiKey(vt);
                ThreatBook.setApiKey(tb);
            }
            applyProxyFromFields();
            updateProxyStatusLabel();

            status("Saved to conf.ini");
            JOptionPane.showMessageDialog(this, "Saved successfully", "Setting", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            ex.printStackTrace();
            error("Failed to save configuration: " + ex.getMessage());
        }
    }

    private void enableProxyInputs(boolean enabled) {
        if (proxyHost != null) proxyHost.setEnabled(enabled);
        if (proxyPort != null) proxyPort.setEnabled(enabled);
        if (proxyUser != null) proxyUser.setEnabled(enabled);
        if (proxyPass != null) proxyPass.setEnabled(enabled);
        if (proxyShow != null) proxyShow.setEnabled(enabled);
    }

    /**
     * Read values from panel and apply to HttpProxyConfig
     */
    private void applyProxyFromFields() {
        boolean en = proxyEnable != null && proxyEnable.isSelected();
        String h = proxyHost != null && proxyHost.getText() != null ? proxyHost.getText().trim() : "";
        int portVal = 0;
        try {
            if (proxyPort != null && proxyPort.getText() != null && !proxyPort.getText().trim().isEmpty()) {
                portVal = Integer.parseInt(proxyPort.getText().trim());
            }
        } catch (Exception ignore) {
        }
        String u = proxyUser != null && proxyUser.getText() != null ? proxyUser.getText().trim() : "";
        char[] pw = proxyPass != null ? proxyPass.getPassword() : new char[0];

        HttpProxyConfig.configure(en, h, portVal, u, pw);
    }

    /**
     * Refresh the real-time proxy status label in Setting panel
     */
    private void updateProxyStatusLabel() {
        if (proxyStateLabel == null) return;
        boolean en = proxyEnable != null && proxyEnable.isSelected();
        String h = proxyHost != null && proxyHost.getText() != null ? proxyHost.getText().trim() : "";
        String p = proxyPort != null && proxyPort.getText() != null ? proxyPort.getText().trim() : "";
        String u = proxyUser != null && proxyUser.getText() != null ? proxyUser.getText().trim() : "";
        boolean hasPort;
        int portVal = 0;
        try {
            portVal = Integer.parseInt(p);
            hasPort = portVal > 0;
        } catch (Exception e) {
            hasPort = false;
        }

        if (!en) {
            proxyStateLabel.setText("Proxy not enabled");
            proxyStateLabel.setForeground(new Color(0x888888));
        } else if (h.isEmpty() || !hasPort) {
            proxyStateLabel.setText("Proxy enabled, but Host/Port not fully configured");
            proxyStateLabel.setForeground(new Color(0xCC8800));
        } else {
            String auth = (u == null || u.isEmpty()) ? "No Auth" : "Auth Enabled";
            proxyStateLabel.setText(String.format("Proxy: Enabled (%s:%d, %s)", h, portVal, auth));
            proxyStateLabel.setForeground(new Color(0x1A7F37));
        }
    }

    // ===== Table styling =====
    private void stylizeTable(JTable table) {
        table.setRowHeight(28);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);

        table.getTableHeader().setReorderingAllowed(true);
        table.getTableHeader().setPreferredSize(
                new Dimension(table.getTableHeader().getPreferredSize().width, 34)
        );
        table.getTableHeader().setFont(table.getTableHeader().getFont().deriveFont(Font.BOLD));
        DefaultTableCellRenderer headerCenter =
                (DefaultTableCellRenderer) table.getTableHeader().getDefaultRenderer();
        headerCenter.setHorizontalAlignment(SwingConstants.CENTER);

        DefaultTableCellRenderer center = new DefaultTableCellRenderer();
        center.setHorizontalAlignment(SwingConstants.CENTER);
        table.setDefaultRenderer(Object.class, center);
        table.setDefaultRenderer(Number.class, center);
        table.setDefaultRenderer(Boolean.class, center);

        for (int i = 0; i < table.getColumnModel().getColumnCount(); i++) {
            TableColumn c = table.getColumnModel().getColumn(i);
            String name = c.getHeaderValue().toString();
            c.setPreferredWidth(preferWidthFor(name));
        }

        table.setShowVerticalLines(true);
        table.setGridColor(new Color(0xDADADA));
    }

    private int preferWidthFor(String col) {
        switch (col) {
            case "risk":
                return 110;
            case "alert_name":
                return 130;
            case "ioc_category":
                return 115;

            // VirusTotal
            case "engine_name":
                return 160;
            case "result":
                return 150;
            case "category":
                return 120;

            // ThreatBook
            case "domain":
                return 140;
            case "judgments":
                return 180;
            case "tags":
                return 200;
            case "permalink":
                return 200;

            default:
                return 110;
        }
    }

    // ===== Single input, simultaneous query: QAX + VirusTotal + ThreatBook =====
    private void triggerSearchBoth() {
        final String raw = inputParam.getText() == null ? "" : inputParam.getText().trim();
        if (raw.isEmpty()) {
            warn("Please enter IP / domain / URL");
            inputParam.requestFocus();
            return;
        }
        setBusy(true, "QAX & VirusTotal & ThreatBook querying…");

        // Domain normalization for VT/TB (URL -> host)
        final String vtKey = deriveDomainForVT(raw);

        lastQueryRaw = raw;
        lastQueryType = detectType(vtKey);  // IPv4 / IPv6 / DOMAIN

        // Pre-clear + 状态
        if (qaxTableModel != null) qaxTableModel.setRowCount(0);
        if (vtModel != null) vtModel.setRowCount(0);
        if (tbDomainModel != null) tbDomainModel.setRowCount(0);
        if (tbIpModel != null) tbIpModel.setRowCount(0);
        if (tbTable != null) {
            tbTable.setModel(tbDomainModel); // 默认域名模型
            stylizeTable(tbTable);
            tbTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
            tbTable.getTableHeader().setResizingAllowed(false);
            installTbResultHighlighter();
        }
        if (qaxStatsLabel != null) qaxStatsLabel.setText("Querying…");
        if (vtStatsLabel != null) vtStatsLabel.setText("Querying…");
        if (tbStatsLabel != null) tbStatsLabel.setText("Querying…");

        final java.util.concurrent.atomic.AtomicInteger pending = new java.util.concurrent.atomic.AtomicInteger(3);

        // QAX
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return QianxinTIP.SendVirusDetection(raw);
            }

            @Override
            protected void done() {
                try {
                    qaxResp = Analyzer.QAX_ParseJson(get());
                    int rows = fillQaxTable(qaxResp);
                    updateQaxTotalBadge(rows);
                    if (qaxStatsLabel != null)
                        qaxStatsLabel.setText(rows > 0 ? ("Total " + rows + " items") : "Mo Data,Clear");
                } catch (Exception ex) {
                    qaxStatsLabel.setText("Query failed — Please check API key / IP whitelist / network");
                    status("QAX error: " + ex.getMessage());
                } finally {
                    if (pending.decrementAndGet() == 0) onAllThreeDone();
                }
            }
        }.execute();

        // VirusTotal
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                String type = detectType(vtKey);
                return ("IPv4".equals(type) || "IPv6".equals(type))
                        ? VirusTotal.getIpReport(vtKey)
                        : VirusTotal.getDomainReport(vtKey);
            }

            @Override
            protected void done() {
                try {
                    String json = get();
                    if (json == null || json.startsWith("Error:") || json.startsWith("Exception:")) {
                        if (vtStatsLabel != null)
                            vtStatsLabel.setText(json == null ? "Query failed (empty return)" : json);
                    } else {
                        vtResp = Analyzer.VirusTotal_ParseJson(json);
                        fillVtViews(vtResp);
                    }
                } catch (Exception ex) {
                    if (vtStatsLabel != null) vtStatsLabel.setText("VT parse failed: " + ex.getMessage());
                    status("VirusTotal error: " + ex.getMessage());
                } finally {
                    if (pending.decrementAndGet() == 0) onAllThreeDone();
                }
            }
        }.execute();

        // ThreatBook
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return ThreatBook.QueryDNS(vtKey);
            }

            @Override
            protected void done() {
                try {
                    String json = get();
                    if (json == null || json.startsWith("Error:") || json.startsWith("Exception:")) {
                        if (tbStatsLabel != null)
                            tbStatsLabel.setText(json == null ? "Query failed (empty return)" : json);
                    } else {
                        tbResp = Analyzer.ThreatBook_ParseJson(json);
                        fillTbViews(vtKey, tbResp);
                    }
                } catch (Exception ex) {
                    if (tbStatsLabel != null) tbStatsLabel.setText("ThreatBook parse failed: " + ex.getMessage());
                    status("ThreatBook error: " + ex.getMessage());
                } finally {
                    if (pending.decrementAndGet() == 0) onAllThreeDone();
                }
            }
        }.execute();
    }

    private void onAllThreeDone() {
        setBusy(false, "QAX & VirusTotal & ThreatBook Search Completed");
        try {
            appendHistoryFromCurrent();
            loadHistoryIntoTable();
        } catch (Exception ignore) {
        }
    }

    // ===== Write QAX data into table (返回写入行数) =====
    private int fillQaxTable(Analyzer.QAXResponseData resp) {
        qaxTableModel.setRowCount(0);
        if (resp == null || resp.data == null || resp.data.isEmpty()) return 0;
        for (Analyzer.AlertData a : resp.data) {
            qaxTableModel.addRow(new Object[]{
                    s(a.risk),
                    s(a.alert_name),
                    s(a.ioc_category),
            });
        }
        return qaxTableModel.getRowCount();
    }

    private void fillVtViews(Analyzer.VirusTotalResponse resp) {
        vtModel.setRowCount(0);
        if (resp == null || resp.data == null || resp.data.attributes == null) {
            if (vtStatsLabel != null) vtStatsLabel.setText("No data");
            return;
        }
        Analyzer.Attributes attrs = resp.data.attributes;
        Analyzer.LastAnalysisStats s = attrs.last_analysis_stats;
        if (s != null) {
            if (vtStatsLabel != null) vtStatsLabel.setText(String.format(
                    "malicious: %d, suspicious: %d, harmless: %d, undetected: %d, timeout: %d",
                    s.malicious, s.suspicious, s.harmless, s.undetected, s.timeout
            ));
            updateVtRiskBadgeFraction(s);
        } else {
            if (vtStatsLabel != null) vtStatsLabel.setText("Stats — N/A");
            updateVtRiskBadgeFraction(null);
        }
        Map<String, Analyzer.EngineResult> results = attrs.last_analysis_results;
        if (results != null && !results.isEmpty()) {
            for (Map.Entry<String, Analyzer.EngineResult> e : results.entrySet()) {
                Analyzer.EngineResult r = e.getValue();
                String engine = (r != null && r.engine_name != null) ? r.engine_name : e.getKey();
                String category = (r != null && r.category != null) ? r.category : "";
                String result = (r != null && r.result != null) ? r.result : "";
                vtModel.addRow(new Object[]{engine, result, category});
            }
        }
        applyVtMaliciousFirstSort();
    }

    private void fillTbViews(String queryKey, Analyzer.ThreatBookResponse resp) {
        tbDomainModel.setRowCount(0);
        tbIpModel.setRowCount(0);

        if (resp == null) {
            if (tbStatsLabel != null) tbStatsLabel.setText("No data");
            tbTable.setModel(tbDomainModel);
            stylizeTable(tbTable);
            tbTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
            tbTable.getTableHeader().setResizingAllowed(false);
            installTbResultHighlighter();
            updateTBRiskBadge(null);
            return;
        }

        if (tbStatsLabel != null) {
            if (resp.verbose_msg != null) {
                tbStatsLabel.setText(String.format("resp=%d, msg=%s", resp.response_code, resp.verbose_msg));
            } else {
                tbStatsLabel.setText(String.format("resp=%d", resp.response_code));
            }
        }

        Analyzer.ThreatBookData data = resp.data;
        if (data == null) {
            tbTable.setModel(tbDomainModel);
            stylizeTable(tbTable);
            tbTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
            tbTable.getTableHeader().setResizingAllowed(false);
            installTbResultHighlighter();
            updateTBRiskBadge(null);
            return;
        }

        boolean filled = false;
        boolean anyMalicious = false;

        // domains
        if (data.domains != null && !data.domains.isEmpty()) {
            tbTable.setModel(tbDomainModel);

            for (Map.Entry<String, Analyzer.ThreatBookDomain> e : data.domains.entrySet()) {
                String domain = e.getKey();
                Analyzer.ThreatBookDomain d = e.getValue();
                if (d == null) continue;

                boolean mal = toBool(d.is_malicious);
                anyMalicious |= mal;

                tbDomainModel.addRow(new Object[]{
                        domain,
                        nvl(d.severity),
                        d.is_malicious
                });
                filled = true;
            }
        }

        // ips
        if (!filled && data.ips != null && !data.ips.isEmpty()) {
            tbTable.setModel(tbIpModel);

            for (Map.Entry<String, Analyzer.ThreatBookIP> e : data.ips.entrySet()) {
                String ip = e.getKey();
                Analyzer.ThreatBookIP d = e.getValue();
                if (d == null) continue;

                boolean mal = toBool(d.is_malicious);
                anyMalicious |= mal;

                tbIpModel.addRow(new Object[]{
                        ip,
                        nvl(d.severity),
                        d.is_malicious
                });
                filled = true;
            }
        }

        if (!filled) {
            tbTable.setModel(tbDomainModel);
            if (tbStatsLabel != null) tbStatsLabel.setText("No matching domain/IP results");
            updateTBRiskBadge(null);
        } else {
            updateTBRiskBadge(anyMalicious);
            if (tbStatsLabel != null) {
                if (anyMalicious) tbStatsLabel.setText(tbStatsLabel.getText() + " | malicious");
                else tbStatsLabel.setText(tbStatsLabel.getText() + " | clean");
            }
        }

        stylizeTable(tbTable);
        tbTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        tbTable.getTableHeader().setResizingAllowed(false);
        installTbResultHighlighter();
    }

    // ===== Common =====
    private String nvl(String s) {
        return s == null ? "" : s;
    }

    private String joinList(List<?> list) {
        if (list == null || list.isEmpty()) return "";
        return list.stream().map(String::valueOf).collect(Collectors.joining(", "));
    }

    private Object s(Object v) {
        return v == null ? "" : v;
    }

    private Icon svg(String path, int w, int h) {
        try {
            java.net.URL url = WorkFrame.class.getResource(path);
            if (url == null) {
                System.err.println("!! Resource NOT found on classpath: " + path);
                return UIManager.getIcon("OptionPane.warningIcon");
            }
            com.formdev.flatlaf.extras.FlatSVGIcon icon = new com.formdev.flatlaf.extras.FlatSVGIcon(url);
            return icon.derive(w, h);
        } catch (Throwable ex) {
            ex.printStackTrace();
            return UIManager.getIcon("OptionPane.errorIcon");
        }
    }

    private Image safeLoadAppIcon() {
        try {
            java.net.URL url = getClass().getResource("/icons/start.png");
            if (url != null) return Toolkit.getDefaultToolkit().getImage(url);
        } catch (Exception ignore) {
        }
        return null;
    }

    private void setBusy(boolean busy, String msg) {
        startSearchBtn.setEnabled(!busy);
        inputParam.setEnabled(!busy);
        clearBtn.setEnabled(!busy);

        status(msg);
        progress.setVisible(busy);
        progress.setIndeterminate(busy);
        setCursor(busy ? Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR) : Cursor.getDefaultCursor());
    }

    private void status(String msg) {
        statusLabel.setText(" " + msg);
    }

    private void warn(String msg) {
        JOptionPane.showMessageDialog(this, msg, "Prompt", JOptionPane.WARNING_MESSAGE);
    }

    //private void error(String msg) { JOptionPane.showMessageDialog(this, msg, "Error", JOptionPane.ERROR_MESSAGE); }
    private void error(String msg) {
        status("Error:" + msg);
    }

    // URL → Domain (for VT/TB)
    private String deriveDomainForVT(String raw) {
        String s = raw == null ? "" : raw.trim();
        try {
            if (s.startsWith("http://") || s.startsWith("https://")) {
                java.net.URI u = java.net.URI.create(s);
                if (u.getHost() != null) return u.getHost();
            }
        } catch (Exception ignore) {
        }
        if (s.contains(".") && !s.matches("\\d+")) return s;
        return s;
    }

    /**
     * 清空输入与三表内容 + 恢复状态栏
     */
    private void clearAllViews() {
        inputParam.setText("");
        if (qaxTableModel != null) qaxTableModel.setRowCount(0);
        if (vtModel != null) vtModel.setRowCount(0);
        if (tbDomainModel != null) tbDomainModel.setRowCount(0);
        if (tbIpModel != null) tbIpModel.setRowCount(0);
        if (qaxStatsLabel != null) qaxStatsLabel.setText("—");
        if (vtStatsLabel != null) vtStatsLabel.setText("—");
        if (tbStatsLabel != null) tbStatsLabel.setText("—");
        clearQaxIpAnalysisBlock();
        clearQaxDomainAnalysisBlock();
        if (analysisOutput != null) analysisOutput.setText("");

        resetBadgesToDefault();
        status("Cleared");
    }

    private void enableCellTooltips(JTable table) {
        table.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override public void mouseMoved(java.awt.event.MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                int col = table.columnAtPoint(e.getPoint());
                if (row >= 0 && col >= 0) {
                    Object v = table.getValueAt(row, col);
                    table.setToolTipText(v == null ? null : String.valueOf(v));
                } else {
                    table.setToolTipText(null);
                }
            }
        });
    }

    /**
     * VirusTotal: 让 result 含 malware/malicious 的行默认排在最上方
     */
    private void applyVtMaliciousFirstSort() {
        if (vtTable == null || vtModel == null) return;

        int resCol = -1;
        for (int i = 0; i < vtTable.getColumnModel().getColumnCount(); i++) {
            Object hv = vtTable.getColumnModel().getColumn(i).getHeaderValue();
            if (hv != null && "result".equalsIgnoreCase(hv.toString())) {
                resCol = i;
                break;
            }
        }
        if (resCol < 0) return;

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(vtModel);
        sorter.setComparator(resCol, (a, b) -> {
            String sa = (a == null ? "" : a.toString()).toLowerCase(Locale.ROOT);
            String sb = (b == null ? "" : b.toString()).toLowerCase(Locale.ROOT);
            boolean aa = sa.contains("malware") || sa.contains("malicious") || sa.contains("suspicious");
            boolean bb = sb.contains("malware") || sb.contains("malicious") || sb.contains("suspicious");
            if (aa != bb) return aa ? -1 : 1;
            return sa.compareTo(sb);
        });

        vtTable.setRowSorter(sorter);
        sorter.setSortKeys(Collections.singletonList(new RowSorter.SortKey(resCol, SortOrder.ASCENDING)));
    }

    /**
     * 简单的圆角卡片容器，带抗锯齿、细边框
     */
    private static class RoundedPanel extends JPanel {
        private final int arc;
        private Color line = new Color(0xDDDDDD);
        private Color fill;

        RoundedPanel(int arc) {
            this.arc = arc;
            setOpaque(false);
            this.fill = UIManager.getColor("Panel.background");
            setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6)); // 原 10/12 → 4/6
        }

        @Override public Dimension getMaximumSize() {
            Dimension pref = getPreferredSize();
            // 宽度放开，高度锁定到首选值
            return new Dimension(Integer.MAX_VALUE, pref.height);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int w = getWidth(), h = getHeight();
            // 阴影可以更淡或去掉，避免看起来“高”
            // g2.setColor(new Color(0, 0, 0, 16)); g2.fillRoundRect(1, 2, w-2, h-2, arc, arc);

            g2.setColor(fill);
            g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc);

            g2.setColor(line);
            g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc);

            g2.dispose();
            super.paintComponent(g);
        }
    }

    private void updateVtRiskBadgeFraction(Analyzer.LastAnalysisStats s) {
        if (vtRiskBadge == null) return;

        if (s == null) {
            vtRiskBadge.setText("—/—");
            if (vtRiskBadge instanceof PillLabel) {
                ((PillLabel) vtRiskBadge).setFill(new Color(0xEEF1F5));
                ((PillLabel) vtRiskBadge).setLine(new Color(0xD0D7DE));
            }
            vtRiskBadge.setForeground(UIManager.getColor("Label.foreground"));
            vtRiskBadge.setToolTipText("No VT stats available");
            return;
        }

        int mal = Math.max(0, s.malicious);
        int sus = Math.max(0, s.suspicious);
        int har = Math.max(0, s.harmless);
        int und = Math.max(0, s.undetected);

        int num = mal + sus;
        int den = num + har + und;

        if (den <= 0) {
            vtRiskBadge.setText("0/0");
            if (vtRiskBadge instanceof PillLabel) {
                ((PillLabel) vtRiskBadge).setFill(new Color(0xEEF1F5));
                ((PillLabel) vtRiskBadge).setLine(new Color(0xD0D7DE));
            }
            vtRiskBadge.setForeground(UIManager.getColor("Label.foreground"));
            vtRiskBadge.setToolTipText("No VT stats available");
            return;
        }

        vtRiskBadge.setText(num + "/" + den);

        // 规则：仅当 “0/94” 时绿色，其余全部红色
        boolean good = (num == 0 && den == 94);
        setPillState(vtRiskBadge, good);

        vtRiskBadge.setToolTipText(String.format(
                "VT: (malicious + suspicious) / total = (%d + %d) / (%d)", mal, sus, den
        ));
    }

    private void updateQaxTotalBadge(int total) {
        if (qaxTotalBadge == null) return;
        if (total < 0) {
            qaxTotalBadge.setText("—");
            setPillState(qaxTotalBadge, true);
            qaxTotalBadge.setToolTipText("QAX no data");
        } else {
            qaxTotalBadge.setText("" + total);
            setPillState(qaxTotalBadge, total == 0);
            qaxTotalBadge.setToolTipText("QAX result " + total);
        }
    }

    private void updateTBRiskBadge(Boolean isMalicious) {
        if (TBRiskBadge == null) return;

        if (isMalicious == null) {
            TBRiskBadge.setText("—");
            if (TBRiskBadge instanceof PillLabel) {
                ((PillLabel) TBRiskBadge).setFill(new Color(0xEEF1F5));
                ((PillLabel) TBRiskBadge).setLine(new Color(0xD0D7DE));
            }
            TBRiskBadge.setForeground(UIManager.getColor("Label.foreground"));
            TBRiskBadge.setToolTipText("ThreatBook: no data");
            return;
        }

        if (isMalicious) {
            TBRiskBadge.setText("malicious");
            setPillState(TBRiskBadge, false);
            TBRiskBadge.setToolTipText("ThreatBook: found malicious indicators");
        } else {
            TBRiskBadge.setText("Clean");
            setPillState(TBRiskBadge, true);
            TBRiskBadge.setToolTipText("ThreatBook: clean");
        }
    }

    // 统一切换 PillLabel 的胶囊配色
    private void setPillState(JLabel label, boolean good) {
        if (label instanceof PillLabel) {
            ((PillLabel) label).setFill(good ? GOOD_FILL : BAD_FILL);
            ((PillLabel) label).setLine(good ? GOOD_LINE : BAD_LINE);
        }
        label.setForeground(good ? GOOD_FG : BAD_FG);
    }

    // 工具：把 ThreatBook 的 is_malicious 值（可能是 boolean / "true" / "1"）统一转成布尔
    private static boolean toBool(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        String s = v.toString().trim();
        return "true".equalsIgnoreCase(s) || "1".equals(s) || "yes".equalsIgnoreCase(s);
    }

    /**
     * 统一搜索条样式：输入框 + Search/Clear 按钮
     */
    private void styleSearchBar(JTextField field, String placeholder, JButton searchBtn, JButton clearBtn) {
        field.putClientProperty(FlatClientProperties.PLACEHOLDER_TEXT, placeholder);
        field.putClientProperty(FlatClientProperties.STYLE,
                "arc:999; focusWidth:1; innerFocusWidth:0; borderWidth:1;");

        searchBtn.putClientProperty(FlatClientProperties.BUTTON_TYPE, "roundRect");
        searchBtn.putClientProperty(FlatClientProperties.STYLE, "arc:999; focusWidth:1; borderWidth:1;");
        searchBtn.setMargin(new Insets(6, 14, 6, 14));
        searchBtn.setMnemonic(KeyEvent.VK_S);

        clearBtn.putClientProperty(FlatClientProperties.BUTTON_TYPE, "roundRect");
        clearBtn.putClientProperty(FlatClientProperties.STYLE, "arc:999; focusWidth:1; borderWidth:1;");
        clearBtn.setMargin(new Insets(6, 12, 6, 12));
    }


    /**
     * QAX: 根据 risk 值上色，并给单元格加细边框让视觉更干净
     */
    private void installQaxRiskHighlighter() {
        if (qaxTable == null || qaxTable.getColumnModel().getColumnCount() == 0) return;

        int colIdx = -1;
        for (int i = 0; i < qaxTable.getColumnModel().getColumnCount(); i++) {
            Object hv = qaxTable.getColumnModel().getColumn(i).getHeaderValue();
            if (hv != null && "risk".equalsIgnoreCase(hv.toString())) {
                colIdx = i;
                break;
            }
        }
        if (colIdx < 0) return;

        final javax.swing.border.Border noFocus =
                UIManager.getBorder("Table.cellNoFocusBorder");

        qaxTable.getColumnModel().getColumn(colIdx).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                setHorizontalAlignment(SwingConstants.CENTER);
                if (isSelected) {
                    setOpaque(true);
                    setBackground(table.getSelectionBackground());
                    setForeground(table.getSelectionForeground());
                    setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(1, 1, 1, 1, table.getGridColor()),
                            BorderFactory.createEmptyBorder(0, 6, 0, 6)
                    ));
                    return c;
                }

                String v = value == null ? "" : value.toString().trim().toLowerCase(Locale.ROOT);
                Color bg = null;
                Color fg = table.getForeground();

                switch (v) {
                    case "critical":
                        bg = Color.RED;
                        fg = Color.WHITE;
                        break;
                    case "high":
                        bg = Color.ORANGE;
                        fg = Color.WHITE;
                        break;
                    case "medium":
                        bg = Color.YELLOW;
                        fg = Color.BLACK;
                        break;
                    case "low":
                        bg = Color.GREEN;
                        fg = Color.BLACK;
                        break;
                    default:
                        setOpaque(false);
                        setForeground(table.getForeground());
                        setBorder(noFocus);
                        return c;
                }

                setOpaque(true);
                setBackground(bg);
                setForeground(fg);
                Color borderColor = bg.darker();
                setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(1, 1, 1, 1, borderColor),
                        BorderFactory.createEmptyBorder(0, 6, 0, 6)
                ));
                return c;
            }
        });
    }

    /**
     * VirusTotal: 根据 result 上色（malware/malicious=红色）
     */
    private void installVtResultHighlighter() {
        if (vtTable == null || vtTable.getColumnModel().getColumnCount() == 0) return;
        int colIdx = -1;
        for (int i = 0; i < vtTable.getColumnModel().getColumnCount(); i++) {
            Object hv = vtTable.getColumnModel().getColumn(i).getHeaderValue();
            if (hv != null && "result".equalsIgnoreCase(hv.toString())) {
                colIdx = i;
                break;
            }
        }
        if (colIdx < 0) return;

        final javax.swing.border.Border noFocus =
                UIManager.getBorder("Table.cellNoFocusBorder");

        vtTable.getColumnModel().getColumn(colIdx).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                setHorizontalAlignment(SwingConstants.CENTER);

                if (isSelected) {
                    setOpaque(true);
                    setBackground(table.getSelectionBackground());
                    setForeground(table.getSelectionForeground());
                    setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createMatteBorder(1, 1, 1, 1, table.getGridColor()),
                            BorderFactory.createEmptyBorder(0, 6, 0, 6)
                    ));
                    return c;
                }

                String v = (value == null ? "" : value.toString()).trim().toLowerCase(Locale.ROOT);
                boolean isBad = v.contains("malware") || v.contains("malicious") || v.contains("suspicious");

                if (!isBad) {
                    setOpaque(false);
                    setForeground(table.getForeground());
                    setBorder(noFocus);
                    return c;
                }

                Color bg = new Color(0xD32F2F);
                setOpaque(true);
                setBackground(bg);
                setForeground(Color.BLACK);
                setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(1, 1, 1, 1, bg.darker()),
                        BorderFactory.createEmptyBorder(0, 6, 0, 6)
                ));
                return c;
            }
        });

        vtTable.setShowVerticalLines(true);
        vtTable.setGridColor(new Color(0xDADADA));
    }

    /**
     * TB table: is_malicious=true 高亮
     */
    private void installTbResultHighlighter() {
        if (tbTable == null || tbTable.getColumnModel().getColumnCount() == 0) return;
        int viewCol = -1;
        for (int i = 0; i < tbTable.getColumnModel().getColumnCount(); i++) {
            Object hv = tbTable.getColumnModel().getColumn(i).getHeaderValue();
            if (hv != null && "is_malicious".equalsIgnoreCase(hv.toString())) {
                viewCol = i;
                break;
            }
        }
        if (viewCol < 0) return;

        tbTable.getColumnModel().getColumn(viewCol).setCellRenderer(new DefaultTableCellRenderer() {
            private final Color MAL_BG = new Color(0xD32F2F);

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                setHorizontalAlignment(SwingConstants.CENTER);
                boolean mal = false;
                if (value != null) {
                    String t = value.toString().trim();
                    mal = "true".equalsIgnoreCase(t) || "1".equals(t);
                }
                if (isSelected) {
                    setOpaque(true);
                    setBackground(table.getSelectionBackground());
                    setForeground(table.getSelectionForeground());
                } else if (mal) {
                    setOpaque(true);
                    setBackground(MAL_BG);
                    setForeground(table.getForeground());
                } else {
                    setOpaque(false);
                    setForeground(table.getForeground());
                }
                return c;
            }
        });
    }

    /* ==============================
     * History 面板与读写
     * ============================== */
    private JPanel buildHistoryCard() {
        JPanel card = new JPanel(new BorderLayout());
        card.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        String[] cols = {"Time", "Query", "Type", "Qi-Anxin TIP", "VirusTotal", "ThreatBook"};
        historyModel = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };
        historyTable = new JTable(historyModel);
        stylizeTable(historyTable);
        historyTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        historyTable.getTableHeader().setResizingAllowed(true);

        JScrollPane sp = new JScrollPane(historyTable);
        sp.setBorder(BorderFactory.createEmptyBorder());

        JToolBar bar = new JToolBar();
        bar.setFloatable(false);
        histReloadBtn = new JButton("Reload");
        histDeleteBtn = new JButton("Delete Selected");
        histClearBtn = new JButton("Clear All");
        histOpenBtn = new JButton("Open File");

        histReloadBtn.addActionListener(e -> loadHistoryIntoTable());
        histDeleteBtn.addActionListener(e -> deleteSelectedHistoryRow());
        histClearBtn.addActionListener(e -> clearHistoryFile());
        histOpenBtn.addActionListener(e -> {
            try {
                Desktop.getDesktop().open(new File(HISTORY_PATH));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Cannot open file: " + ex.getMessage(),
                        "Open History", JOptionPane.WARNING_MESSAGE);
            }
        });

        bar.add(histReloadBtn);
        bar.add(histDeleteBtn);
        bar.add(histClearBtn);
        bar.addSeparator();
        bar.add(histOpenBtn);

        card.add(bar, BorderLayout.NORTH);
        card.add(sp, BorderLayout.CENTER);
        return card;
    }

    private void appendHistoryFromCurrent() {
        String timeIso = ZonedDateTime.now(ZoneId.systemDefault())
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        int qaxTotal = (qaxTableModel != null) ? qaxTableModel.getRowCount() : -1;

        int vtM = -1, vtS = -1, vtH = -1, vtU = -1;
        if (vtResp != null && vtResp.data != null && vtResp.data.attributes != null
                && vtResp.data.attributes.last_analysis_stats != null) {
            Analyzer.LastAnalysisStats s = vtResp.data.attributes.last_analysis_stats;
            vtM = s.malicious;
            vtS = s.suspicious;
            vtH = s.harmless;
            vtU = s.undetected;
        }

        String tbStatus = deriveTbStatus(tbResp);
        boolean tbMal = "malicious".equals(tbStatus);

        String jsonLine = "{"
                + "\"time\":\"" + jsonEscape(timeIso) + "\","
                + "\"query\":\"" + jsonEscape(lastQueryRaw) + "\","
                + "\"type\":\"" + jsonEscape(lastQueryType) + "\","
                + "\"qax_total\":" + qaxTotal + ","
                + "\"vt_malicious\":" + vtM + ","
                + "\"vt_suspicious\":" + vtS + ","
                + "\"vt_harmless\":" + vtH + ","
                + "\"vt_undetected\":" + vtU + ","
                + "\"tb_status\":\"" + jsonEscape(tbStatus) + "\","
                + "\"tb_malicious\":" + tbMal
                + "}";

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(HISTORY_PATH, StandardCharsets.UTF_8, true))) {
            bw.write(jsonLine);
            bw.newLine();
        } catch (IOException e) {
            System.err.println("[History] write failed: " + e.getMessage());
        }
    }

    private void loadHistoryIntoTable() {
        historyModel.setRowCount(0);
        historyRawLines.clear();

        File f = new File(HISTORY_PATH);
        if (!f.exists()) return;

        try {
            java.util.List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
            historyRawLines.addAll(lines);

            for (String line : lines) {
                if (line == null || line.trim().isEmpty()) continue;

                String time = extractString(line, "time");
                String query = extractString(line, "query");
                String type = extractString(line, "type");

                int qax = extractInt(line, "qax_total", -1);
                int m = extractInt(line, "vt_malicious", -1);
                int s = extractInt(line, "vt_suspicious", -1);
                int h = extractInt(line, "vt_harmless", -1);
                int u = extractInt(line, "vt_undetected", -1);

                String vtCell;
                if (m < 0 || s < 0 || h < 0 || u < 0) {
                    vtCell = "—";
                } else {
                    int num = Math.max(0, m) + Math.max(0, s);
                    int den = num + Math.max(0, h) + Math.max(0, u);
                    vtCell = den > 0 ? (num + "/" + den) : "—";
                }

                String tbStatus = extractString(line, "tb_status");
                String tbCell;
                if (tbStatus != null && !tbStatus.isEmpty()) {
                    tbCell = tbStatus;
                } else {
                    boolean tb = extractBool(line, "tb_malicious", false);
                    tbCell = tb ? "malicious" : "clean";
                }

                historyModel.addRow(new Object[]{
                        time, query, type,
                        (qax >= 0 ? qax : "—"),
                        vtCell, tbCell
                });
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Load history failed: " + e.getMessage(),
                    "History", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void deleteSelectedHistoryRow() {
        int viewRow = historyTable.getSelectedRow();
        if (viewRow < 0) {
            JOptionPane.showMessageDialog(this, "Please select a row to delete.", "History", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int modelRow = historyTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= historyRawLines.size()) return;

        historyRawLines.remove(modelRow);
        historyModel.removeRow(modelRow);

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(HISTORY_PATH, StandardCharsets.UTF_8, false))) {
            for (String ln : historyRawLines) {
                if (ln != null && !ln.trim().isEmpty()) {
                    bw.write(ln);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Delete failed: " + e.getMessage(), "History", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void clearHistoryFile() {
        int ok = JOptionPane.showConfirmDialog(this,
                "Clear all history? This cannot be undone.",
                "History", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) return;

        try {
            Files.write(new File(HISTORY_PATH).toPath(), new byte[0]);
            loadHistoryIntoTable();
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Clear failed: " + e.getMessage(), "History", JOptionPane.WARNING_MESSAGE);
        }
    }

    /* ==============================
     * 解析/工具
     * ============================== */
    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String extractString(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"(.*?)\"");
        Matcher m = p.matcher(json);
        if (m.find()) {
            String v = m.group(1);
            return v.replace("\\\"", "\"").replace("\\\\", "\\");
        }
        return "";
    }

    private static int extractInt(String json, String key, int def) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)");
        Matcher m = p.matcher(json);
        if (m.find()) {
            try {
                return Integer.parseInt(m.group(1));
            } catch (Exception ignore) {
            }
        }
        return def;
    }

    private static boolean extractBool(String json, String key, boolean def) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|false)");
        Matcher m = p.matcher(json);
        if (m.find()) return Boolean.parseBoolean(m.group(1));
        return def;
    }

    private boolean computeTbAnyMalicious(Analyzer.ThreatBookResponse resp) {
        if (resp == null || resp.data == null) return false;
        boolean any = false;
        if (resp.data.domains != null && !resp.data.domains.isEmpty()) {
            for (Map.Entry<String, Analyzer.ThreatBookDomain> e : resp.data.domains.entrySet()) {
                Analyzer.ThreatBookDomain d = e.getValue();
                if (d != null && toBool(d.is_malicious)) {
                    any = true;
                    break;
                }
            }
        }
        if (!any && resp.data.ips != null && !resp.data.ips.isEmpty()) {
            for (Map.Entry<String, Analyzer.ThreatBookIP> e : resp.data.ips.entrySet()) {
                Analyzer.ThreatBookIP d = e.getValue();
                if (d != null && toBool(d.is_malicious)) {
                    any = true;
                    break;
                }
            }
        }
        return any;
    }

    /**
     * ThreatBook 状态：malicious / clean / failure（无结果或出错）
     */
    private String deriveTbStatus(Analyzer.ThreatBookResponse resp) {
        if (resp == null || resp.data == null) return "failure";
        boolean hasDomain = resp.data.domains != null && !resp.data.domains.isEmpty();
        boolean hasIp = resp.data.ips != null && !resp.data.ips.isEmpty();
        if (!hasDomain && !hasIp) return "failure";
        return computeTbAnyMalicious(resp) ? "malicious" : "clean";
    }

    /**
     * 若 conf.ini 不存在则写入一个默认模板
     */
    private void ensureConfFileExists() {
        try {
            File f = new File(CONF_PATH);
            if (f.exists()) return;

            File parent = f.getParentFile();
            if (parent != null) parent.mkdirs();

            Properties p = new Properties();

            p.setProperty(KEY_QAX, "123456");
            p.setProperty(KEY_VT, "123456");
            p.setProperty(KEY_TB, "123456");
            p.setProperty(KEY_IPQS, "123456");

            p.setProperty(KEY_PROXY_ENABLED, "false");
            p.setProperty(KEY_PROXY_HOST, "127.0.0.1");
            p.setProperty(KEY_PROXY_PORT, "8081");
            p.setProperty(KEY_PROXY_USER, "proxyuser");
            p.setProperty(KEY_PROXY_PASS, "123456");

            try (FileOutputStream out = new FileOutputStream(f)) {
                p.store(out, "VirusTool API Keys (QAX/VT/TB/IPQS) & HTTP Proxy");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            error("Failed to create default conf.ini: " + ex.getMessage());
        }
    }

    private void resetBadgesToDefault() {
        vtRiskBadge.setText("-");
        qaxTotalBadge.setText("-");
        TBRiskBadge.setText("-");
        setBadgeNeutral(vtRiskBadge);
        setBadgeNeutral(qaxTotalBadge);
        setBadgeNeutral(TBRiskBadge);
    }

    private void setBadgeNeutral(JLabel badge) {
        if (badge instanceof PillLabel) {
            ((PillLabel) badge).setFill(new Color(0xEEF1F5));
            ((PillLabel) badge).setLine(new Color(0xD0D7DE));
        }
        badge.setForeground(UIManager.getColor("Label.foreground"));
    }

    /* ==============================
     * 输入类型识别（保留你的签名与逻辑）
     * ============================== */
    public static String detectType(String input) {
        if (IPV4_PATTERN.matcher(input).matches()) {
            return "IPv4";
        } else if (IPV6_PATTERN.matcher(input).matches() && input.contains(":")) {
            return "IPv6";
        } else {
            return "DOMAIN";
        }
    }

    /** 切换到 “Analysis” 选项卡；若不存在则创建后切换 */
    private void switchToAnalysisTab() {
        if (tabbedPane == null) return;


        int idx = tabbedPane.indexOfTab("Analysis");
        if (idx >= 0) {
            tabbedPane.setSelectedIndex(idx);
            return;
        }
    }
}
