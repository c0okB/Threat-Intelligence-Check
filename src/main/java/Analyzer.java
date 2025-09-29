import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public class Analyzer {

    // ====================== QAX 解析 ======================
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class QAXResponseData {
        public int status;
        public String msg;
        public java.util.List<AlertData> data;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AlertData {
        public String alert_name;
        public String campaign;
        public String confidence;
        public String current_status;
        public String etime;
        public String id;
        public java.util.List<String> ioc;
        public String ioc_category;
        public String kill_chain;
        public java.util.List<String> malicious_family;
        public String malicious_type;
        public String platform;
        public String risk;
        public java.util.List<String> tag;
        public boolean targeted;
        public String TTP;
        public int tlp;
    }

    /**
     * 解析 QAX JSON
     */
    public static QAXResponseData QAX_ParseJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, QAXResponseData.class);
    }

    // ====================== VirusTotal 解析 ======================
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class VirusTotalResponse {
        public Data data;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Data {
        public String id;
        public String type;
        public Attributes attributes;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Attributes {
        public LastAnalysisStats last_analysis_stats;
        public Map<String, EngineResult> last_analysis_results;
        public int reputation;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class LastAnalysisStats {
        public int malicious;
        public int harmless;
        public int undetected;
        public int suspicious;
        public int timeout;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class EngineResult {
        public String category;
        public String result;
        public String engine_name;
    }

    // ====================== QAX - AnalysisDomain (CheckUrls) 解析 ======================
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class QAXDomainCheckResponse {
        public java.util.List<Reply> replies;

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Reply {
            public int index;
            public Meta meta;
            public UssSection uss;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Meta {
            public MetaInner meta;
            public java.util.List<Object> slice_infos;
            public Status status;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class MetaInner {
            // 注意：服务端存在字段拼写差异（如 contry / timezion）
            public String china_admin_code;
            public String city;
            public String continent_code;
            public String contry;         // 原样保留
            public String country_code;
            public String create_time;
            public String description;
            public String idd_code;
            public String industry;
            public String isp_domain;
            public double latitude;
            public double longitude;
            public String online_status;
            public String owner;
            public String region;
            public String timezion;       // 原样保留
            public String update_time;
            public String utc_offset;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Status {
            public int code;
            public java.util.List<Object> details;
            public String message;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class UssSection {
            public java.util.List<Object> slice_infos;
            public Status status;
            public Uss uss;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Uss {
            public int category;                 // e.g. 10000
            public String detect_region;
            public String fake_brand;
            public String first_detect_time;
            public String last_update_time;
            public int level;                    // e.g. 0
            public String official_site;
            public String page_title;
            public String top_domain;            // e.g. "github.com"
            public String url;                   // e.g. "github.com"
        }
    }

    /** 解析 QianxinTIP.AnalysisDomain(JSON) */
    public static QAXDomainCheckResponse QAX_AnalysisDomain_ParseJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, QAXDomainCheckResponse.class);
    }


    // ====================== QAX - AnalysisIP (Reputation) 解析 ======================
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class QAXIpReputationResponse {
        public int status;                  // e.g. 10000
        public String msg;                  // e.g. "Success"
        public java.util.Map<String, IpRecord> data; // key 为 IP 字符串

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class IpRecord {
            public Geo geo;
            public Whois whois;
            @JsonProperty("normal_info")
            public NormalInfo normalInfo;

            @JsonProperty("malicious_info")
            public java.util.List<Object> maliciousInfo; // 样例为空数组，先用 Object 占位

            @JsonProperty("ipservice_benign_info")
            public java.util.List<Object> ipserviceBenignInfo;

            @JsonProperty("ipservice_unknown_info")
            public java.util.List<Object> ipserviceUnknownInfo;

            @JsonProperty("ip_infrastructure_info")
            public java.util.List<IpInfra> ipInfrastructureInfo;

            @JsonProperty("vuln_info")
            public java.util.List<Object> vulnInfo;

            @JsonProperty("compromised_info")
            public java.util.List<Compromised> compromisedInfo;

            public java.util.List<Object> compromise; // 样例里也有该字段

            @JsonProperty("summary_info")
            public Summary summaryInfo;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Geo {
            public String city;
            public String country;
            public String latitude;
            public String longitude;
            public String province;
            public String continent;
            public String district;
            @JsonProperty("detail_address")
            public String detailAddress;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Whois {
            @JsonProperty("net_range")
            public String netRange;
            public java.util.List<String> cidr;
            @JsonProperty("net_name")
            public String netName;
            public java.util.List<String> parent;
            @JsonProperty("net_type")
            public String netType;
            public String organization;
            public String ref;
            public String regdate;
            public String updated;
            @JsonProperty("whois_server")
            public String whoisServer;
            public String rir;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class NormalInfo {
            public String asn;
            @JsonProperty("asn_org")
            public String asnOrg;
            public String owner;
            public java.util.List<String> hostnames;
            public String actor;

            // 原来是 List<String>，会在对象数组时崩
            @JsonProperty("current_domain")
            public java.util.List<CurrentDomain> currentDomain;

            @JsonProperty("user_type")
            public String userType;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class CurrentDomain {
            public String domain;
            @JsonProperty("first_seen")
            public String firstSeen;
            @JsonProperty("last_seen")
            public String lastSeen;

            // 方便日志或 UI 调试时直接看到域名
            @Override public String toString() { return domain == null ? "" : domain; }
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class IpInfra {
            public String name;     // e.g. "MOBILE_NETWORK"
            public String time;     // e.g. "2025-04-09"
            public Context context;

            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class Context {
                public String confidence;   // e.g. "中"
                @JsonProperty("first_seen")
                public long firstSeen;
                @JsonProperty("last_seen")
                public long lastSeen;
                public String status;       // e.g. "ACTIVE"
            }
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Compromised {
            @JsonProperty("latest_compromised_time")
            public String latestCompromisedTime;
            @JsonProperty("malware_type")
            public String malwareType;
            @JsonProperty("malware_family")
            public String malwareFamily;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Summary {
            public String ip;
            public String reputation; // e.g. "unknown"
            @JsonProperty("latest_reputation_time")
            public String latestReputationTime;

            @JsonProperty("malicious_label")
            public java.util.List<String> maliciousLabel;

            @JsonProperty("ipservice_benign_label")
            public java.util.List<String> ipserviceBenignLabel;

            @JsonProperty("ipservice_unknown_label")
            public java.util.List<String> ipserviceUnknownLabel;

            @JsonProperty("ip_infrastructure_label")
            public java.util.List<String> ipInfrastructureLabel;
        }
    }

    /** 解析 QianxinTIP.AnalysisIP(JSON) */
    public static QAXIpReputationResponse QAX_AnalysisIP_ParseJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, QAXIpReputationResponse.class);
    }

    /**
     * 解析 VirusTotal JSON 字符串为对象
     *
     * @param json 输入的 JSON
     * @return VirusTotalResponse 对象
     * @throws Exception 解析失败抛出异常
     */
    public static VirusTotalResponse VirusTotal_ParseJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, VirusTotalResponse.class);
    }

    // ====================== ThreatBook 解析 ======================
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ThreatBookResponse {
        public ThreatBookData data;
        public int response_code;
        public String verbose_msg;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ThreatBookData {
        // 域名返回
        public Map<String, ThreatBookDomain> domains;
        // IP 返回（你提供的样例结构）
        public Map<String, ThreatBookIP> ips;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ThreatBookDomain {
        public String severity;
        public java.util.List<String> judgments;
        public java.util.List<TagsClass> tags_classes;
        public Rank rank;                 // 域名才有
        public Categories categories;     // 域名才有
        public String permalink;
        public String confidence_level;
        public boolean is_malicious;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ThreatBookIP {
        public String severity;
        public java.util.List<String> judgments;
        public java.util.List<TagsClass> tags_classes; // 也可能有，但常为空数组
        public String permalink;
        public String confidence_level;
        public boolean is_malicious;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TagsClass {
        public java.util.List<String> tags;
        public String tags_type; // e.g. "virus_family"
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Rank {
        public RankItem alexa_rank;
        public RankItem umbrella_rank;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class RankItem {
        public int global_rank; // -1 表示无
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Categories {
        public java.util.List<String> first_cats; // e.g. ["Tool"]
        public String second_cats;                // e.g. "Computer and Internet Info"
    }

    /** 解析 ThreatBook JSON 字符串为对象 */
    public static ThreatBookResponse ThreatBook_ParseJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, ThreatBookResponse.class);
    }


    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class IPQSResponse {
        public boolean success;
        public String message;
        public int fraud_score;

        public String country_code;
        public String region;
        public String city;

        // 注意：返回里是大写的 "ISP" 和 "ASN"
        @JsonProperty("ISP")
        public String ISP;
        @JsonProperty("ASN")
        public int ASN;

        public String operating_system;
        public String browser;
        public String organization;

        @JsonProperty("is_crawler")
        public boolean is_crawler;

        public String timezone;
        public boolean mobile;
        public String host;

        public boolean proxy;
        public boolean vpn;
        public boolean tor;

        @JsonProperty("active_vpn")
        public boolean active_vpn;
        @JsonProperty("active_tor")
        public boolean active_tor;

        public String device_brand;
        public String device_model;

        public boolean recent_abuse;
        public boolean bot_status;

        public String connection_type;
        public String abuse_velocity;
        public String zip_code;

        public double latitude;
        public double longitude;

        public java.util.List<String> abuse_events;
        public String request_id;
    }

    /** 解析 IPQualityScore 的 queryIp JSON 字符串为对象 */
    public static IPQSResponse IPQS_ParseJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, IPQSResponse.class);
    }
}
