-- Missing tables for GCP deployment
-- These tables exist on PC1/PC2 but weren't created on GCP

CREATE TABLE IF NOT EXISTS clif_logs.asset_criticality ON CLUSTER 'clif_cluster'
(
    hostname_pattern    String                                     CODEC(ZSTD(1)),
    asset_class         LowCardinality(String)                     CODEC(ZSTD(1)),
    multiplier          Float32       DEFAULT 1.0                  CODEC(ZSTD(1)),
    updated_at          DateTime64(3) DEFAULT now64()              CODEC(Delta, ZSTD(3))
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/asset_criticality',
    '{replica}',
    updated_at
)
ORDER BY (hostname_pattern)
SETTINGS index_granularity = 256;

CREATE TABLE IF NOT EXISTS clif_logs.triage_scores ON CLUSTER 'clif_cluster'
(
    score_id          UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    event_id          UUID                                        CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    source_type       LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    hostname          String        DEFAULT ''                    CODEC(ZSTD(1)),
    source_ip         String        DEFAULT ''                    CODEC(ZSTD(1)),
    user_id           String        DEFAULT ''                    CODEC(ZSTD(1)),
    template_id       String        DEFAULT ''                    CODEC(ZSTD(1)),
    template_rarity   Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    combined_score    Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    lgbm_score        Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    eif_score         Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    arf_score         Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    score_std_dev     Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    agreement         Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    ci_lower          Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    ci_upper          Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    asset_multiplier  Float32       DEFAULT 1.0                   CODEC(ZSTD(1)),
    adjusted_score    Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    action            Enum8('discard'=0, 'monitor'=1, 'escalate'=2)  CODEC(ZSTD(1)),
    ioc_match         UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    ioc_confidence    UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    mitre_tactic      LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    mitre_technique   LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    shap_top_features String        DEFAULT ''                    CODEC(ZSTD(3)),
    shap_summary      String        DEFAULT ''                    CODEC(ZSTD(3)),
    features_stale    UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    model_version     String        DEFAULT ''                    CODEC(ZSTD(1)),
    disagreement_flag UInt8         DEFAULT 0                     CODEC(ZSTD(1)),

    INDEX idx_source_type source_type     TYPE set(50)            GRANULARITY 4,
    INDEX idx_action      action          TYPE set(5)             GRANULARITY 4,
    INDEX idx_combined    combined_score  TYPE minmax             GRANULARITY 4,
    INDEX idx_adjusted    adjusted_score  TYPE minmax             GRANULARITY 4,
    INDEX idx_template    template_id     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_hostname    hostname        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_ioc         ioc_match       TYPE set(2)             GRANULARITY 4,
    INDEX idx_disagree    disagreement_flag TYPE set(2)           GRANULARITY 4,
    INDEX idx_event_id    event_id        TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/triage_scores',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (source_type, action, timestamp, score_id)
TTL
    toDateTime(timestamp) + INTERVAL 7  DAY TO VOLUME 'warm',
    toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;

CREATE TABLE IF NOT EXISTS clif_logs.hunter_investigations ON CLUSTER 'clif_cluster'
(
    investigation_id  UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    alert_id          UUID                                        CODEC(ZSTD(3)),
    started_at        DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    completed_at      Nullable(DateTime64(3))                     CODEC(ZSTD(3)),
    status            Enum8('pending'=0, 'running'=1, 'completed'=2, 'failed'=3, 'timeout'=4) CODEC(ZSTD(1)),
    hostname          String        DEFAULT ''                    CODEC(ZSTD(1)),
    source_ip         String        DEFAULT ''                    CODEC(ZSTD(1)),
    user_id           String        DEFAULT ''                    CODEC(ZSTD(1)),
    trigger_score     Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    severity          Enum8('info'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4) CODEC(ZSTD(1)),
    finding_type      LowCardinality(String) DEFAULT ''           CODEC(ZSTD(1)),
    summary           String        DEFAULT ''                    CODEC(ZSTD(3)),
    evidence_json     String        DEFAULT ''                    CODEC(ZSTD(3)),
    correlated_events Array(UUID)                                 CODEC(ZSTD(3)),
    mitre_tactics     Array(String)                               CODEC(ZSTD(1)),
    mitre_techniques  Array(String)                               CODEC(ZSTD(1)),
    recommended_action String       DEFAULT ''                    CODEC(ZSTD(3)),
    confidence        Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),

    INDEX idx_status   status       TYPE set(10)                  GRANULARITY 1,
    INDEX idx_severity severity     TYPE set(10)                  GRANULARITY 1,
    INDEX idx_host     hostname     TYPE bloom_filter(0.01)       GRANULARITY 4
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/hunter_investigations',
    '{replica}'
)
PARTITION BY toYYYYMMDD(started_at)
ORDER BY (status, started_at, investigation_id)
TTL
    toDateTime(started_at) + INTERVAL 30 DAY TO VOLUME 'warm',
    toDateTime(started_at) + INTERVAL 90 DAY TO VOLUME 'cold',
    toDateTime(started_at) + INTERVAL 365 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;

CREATE TABLE IF NOT EXISTS clif_logs.verifier_results ON CLUSTER 'clif_cluster'
(
    verification_id   UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    investigation_id  UUID                                        CODEC(ZSTD(3)),
    alert_id          UUID                                        CODEC(ZSTD(3)),
    started_at        DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    completed_at      Nullable(DateTime64(3))                     CODEC(ZSTD(3)),
    status            Enum8('pending'=0, 'running'=1, 'verified'=2, 'false_positive'=3, 'inconclusive'=4, 'failed'=5) CODEC(ZSTD(1)),
    verdict           Enum8('true_positive'=1, 'false_positive'=2, 'inconclusive'=3) CODEC(ZSTD(1)),
    confidence        Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    evidence_verified UInt8         DEFAULT 0                     CODEC(ZSTD(1)),
    merkle_batch_ids  Array(String)                               CODEC(ZSTD(3)),
    timeline_json     String        DEFAULT ''                    CODEC(ZSTD(3)),
    ioc_correlations  String        DEFAULT ''                    CODEC(ZSTD(3)),
    priority          Enum8('P4'=0, 'P3'=1, 'P2'=2, 'P1'=3)     CODEC(ZSTD(1)),
    recommended_action String       DEFAULT ''                    CODEC(ZSTD(3)),
    analyst_summary   String        DEFAULT ''                    CODEC(ZSTD(3)),
    report_narrative  String        DEFAULT ''                    CODEC(ZSTD(3)),
    evidence_json     String        DEFAULT ''                    CODEC(ZSTD(3)),

    INDEX idx_verdict  verdict      TYPE set(5)                   GRANULARITY 1,
    INDEX idx_priority priority     TYPE set(5)                   GRANULARITY 1,
    INDEX idx_status   status       TYPE set(10)                  GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/verifier_results',
    '{replica}'
)
PARTITION BY toYYYYMMDD(started_at)
ORDER BY (verdict, started_at, verification_id)
TTL
    toDateTime(started_at) + INTERVAL 30 DAY TO VOLUME 'warm',
    toDateTime(started_at) + INTERVAL 90 DAY TO VOLUME 'cold',
    toDateTime(started_at) + INTERVAL 365 DAY DELETE
SETTINGS
    index_granularity      = 8192,
    storage_policy         = 'clif_tiered',
    merge_with_ttl_timeout = 3600;

CREATE TABLE IF NOT EXISTS clif_logs.feedback_labels ON CLUSTER 'clif_cluster'
(
    feedback_id       UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    event_id          UUID                                        CODEC(ZSTD(3)),
    score_id          Nullable(UUID)                              CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    label             Enum8('true_positive'=1, 'false_positive'=2, 'unknown'=3) CODEC(ZSTD(1)),
    confidence        Enum8('low'=1, 'medium'=2, 'high'=3)       CODEC(ZSTD(1)),
    analyst_id        String        DEFAULT ''                    CODEC(ZSTD(1)),
    notes             String        DEFAULT ''                    CODEC(ZSTD(3)),
    original_combined Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    original_lgbm     Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    original_eif      Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),
    original_arf      Float32       DEFAULT 0.0                   CODEC(ZSTD(1)),

    INDEX idx_label    label        TYPE set(5)                   GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/feedback_labels',
    '{replica}'
)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (label, timestamp, feedback_id)
TTL toDateTime(timestamp) + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 256;

CREATE TABLE IF NOT EXISTS clif_logs.dead_letter_events ON CLUSTER 'clif_cluster'
(
    dl_id             UUID          DEFAULT generateUUIDv4()      CODEC(ZSTD(3)),
    timestamp         DateTime64(3) DEFAULT now64()               CODEC(Delta, ZSTD(3)),
    failed_stage      LowCardinality(String)                      CODEC(ZSTD(1)),
    source_topic      LowCardinality(String)                      CODEC(ZSTD(1)),
    error_message     String        DEFAULT ''                    CODEC(ZSTD(3)),
    raw_payload       String        DEFAULT ''                    CODEC(ZSTD(3)),
    retry_count       UInt8         DEFAULT 0                     CODEC(ZSTD(1)),

    INDEX idx_stage    failed_stage TYPE set(20)                  GRANULARITY 1
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/dead_letter_events',
    '{replica}'
)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (failed_stage, timestamp, dl_id)
TTL toDateTime(timestamp) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 256;

CREATE TABLE IF NOT EXISTS clif_logs.mitre_mapping_rules ON CLUSTER 'clif_cluster'
(
    rule_id           String                                       CODEC(ZSTD(1)),
    priority          UInt8         DEFAULT 100                    CODEC(ZSTD(1)),
    trigger_features  Array(String)                                CODEC(ZSTD(1)),
    trigger_threshold Float32       DEFAULT 0.0                    CODEC(ZSTD(1)),
    mitre_id          String                                       CODEC(ZSTD(1)),
    mitre_name        String                                       CODEC(ZSTD(1)),
    mitre_tactic      String        DEFAULT ''                     CODEC(ZSTD(1)),
    confidence        Enum8('LOW'=1, 'MEDIUM'=2, 'HIGH'=3)        CODEC(ZSTD(1)),
    description       String        DEFAULT ''                     CODEC(ZSTD(3)),
    updated_at        DateTime64(3) DEFAULT now64()                CODEC(Delta, ZSTD(3))
)
ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/tables/{shard}/mitre_mapping_rules',
    '{replica}',
    updated_at
)
ORDER BY (priority, rule_id)
SETTINGS index_granularity = 256;

INSERT INTO clif_logs.mitre_mapping_rules (rule_id, priority, trigger_features, trigger_threshold, mitre_id, mitre_name, mitre_tactic, confidence, description)
VALUES
    ('brute_force',       10, ['event_freq_1m', 'template_auth'],      10.0, 'T1110', 'Brute Force',                   'credential-access',    'HIGH',   'High-freq auth failures from single entity'),
    ('lateral_movement',  20, ['unique_hosts_5m', 'template_lateral'], 3.0,  'T1021', 'Remote Services',               'lateral-movement',     'HIGH',   'Multi-host lateral movement detection'),
    ('c2_traffic',        30, ['known_malicious_ip', 'outbound'],      1.0,  'T1071', 'Application Layer Protocol',    'command-and-control',  'HIGH',   'Outbound traffic to known-malicious IP'),
    ('account_creation',  40, ['template_user_created', 'off_hours'],  1.0,  'T1136', 'Create Account',                'persistence',          'MEDIUM', 'New account creation during off-hours'),
    ('privilege_esc',     50, ['template_priv_escalation'],            1.0,  'T1068', 'Exploitation for Priv Esc',     'privilege-escalation',  'HIGH',   'Privilege escalation template detected'),
    ('data_exfil',        60, ['template_data_exfil', 'large_payload'],1.0,  'T1041', 'Exfiltration Over C2 Channel',  'exfiltration',         'HIGH',   'Data exfiltration with large payload'),
    ('zero_day',          70, ['ae_high', 'lgbm_low', 'novel_template'],0.0,'T1190', 'Exploit Public-Facing App',     'initial-access',       'MEDIUM', 'Autoencoder anomaly + unknown to LightGBM'),
    ('network_recon',     80, ['template_port_scan', 'multi_port'],    1.0,  'T1046', 'Network Service Discovery',     'discovery',            'HIGH',   'Port scan / network reconnaissance'),
    ('model_disagreement',90, ['std_dev_high'],                        0.35, 'UNKNOWN_TTP', 'Model Disagreement',      '',                     'LOW',    'High model disagreement — requires analyst review');

CREATE TABLE IF NOT EXISTS clif_logs.features_entity_freq ON CLUSTER 'clif_cluster'
(
    window         DateTime       CODEC(Delta, ZSTD(1)),
    source_ip      String         CODEC(ZSTD(1)),
    user_id        String         CODEC(ZSTD(1)),
    hostname       String         CODEC(ZSTD(1)),
    event_count    SimpleAggregateFunction(sum, UInt64),
    unique_actions AggregateFunction(uniq, String),
    min_severity   SimpleAggregateFunction(min, UInt8),
    max_severity   SimpleAggregateFunction(max, UInt8)
)
ENGINE = ReplicatedAggregatingMergeTree(
    '/clickhouse/tables/{shard}/features_entity_freq',
    '{replica}'
)
PARTITION BY toYYYYMMDD(window)
ORDER BY (source_ip, user_id, hostname, window)
TTL window + INTERVAL 7 DAY DELETE
SETTINGS index_granularity = 256;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.features_entity_freq_security_mv ON CLUSTER 'clif_cluster'
TO clif_logs.features_entity_freq
AS
SELECT
    toStartOfMinute(timestamp) AS window,
    toString(ip_address) AS source_ip,
    user_id,
    hostname,
    count() AS event_count,
    uniqState(category) AS unique_actions,
    min(severity) AS min_severity,
    max(severity) AS max_severity
FROM clif_logs.security_events
GROUP BY window, source_ip, user_id, hostname;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.features_entity_freq_network_mv ON CLUSTER 'clif_cluster'
TO clif_logs.features_entity_freq
AS
SELECT
    toStartOfMinute(timestamp) AS window,
    toString(src_ip) AS source_ip,
    '' AS user_id,
    hostname,
    count() AS event_count,
    uniqState(protocol) AS unique_actions,
    toUInt8(0) AS min_severity,
    max(toUInt8(if(is_suspicious = 1, 4, 0))) AS max_severity
FROM clif_logs.network_events
GROUP BY window, source_ip, user_id, hostname;

CREATE MATERIALIZED VIEW IF NOT EXISTS clif_logs.features_entity_freq_process_mv ON CLUSTER 'clif_cluster'
TO clif_logs.features_entity_freq
AS
SELECT
    toStartOfMinute(timestamp) AS window,
    '' AS source_ip,
    toString(uid) AS user_id,
    hostname,
    count() AS event_count,
    uniqState(binary_path) AS unique_actions,
    toUInt8(0) AS min_severity,
    max(toUInt8(if(is_suspicious = 1, 4, 0))) AS max_severity
FROM clif_logs.process_events
GROUP BY window, source_ip, user_id, hostname;

CREATE TABLE IF NOT EXISTS clif_logs.features_template_rarity ON CLUSTER 'clif_cluster'
(
    template_id      String         CODEC(ZSTD(1)),
    source_type      LowCardinality(String)  CODEC(ZSTD(1)),
    occurrence_count SimpleAggregateFunction(sum, UInt64),
    first_seen       SimpleAggregateFunction(min, DateTime),
    last_seen        SimpleAggregateFunction(max, DateTime)
)
ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/tables/{shard}/features_template_rarity',
    '{replica}'
)
ORDER BY (template_id, source_type)
TTL last_seen + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 256;

CREATE TABLE IF NOT EXISTS clif_logs.features_entity_baseline ON CLUSTER 'clif_cluster'
(
    user_id          String         CODEC(ZSTD(1)),
    hostname         String         CODEC(ZSTD(1)),
    hour_of_day      UInt8          CODEC(ZSTD(1)),
    day_count        SimpleAggregateFunction(sum, UInt64),
    event_sum        SimpleAggregateFunction(sum, UInt64),
    event_sum_sq     SimpleAggregateFunction(sum, UInt64)
)
ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/tables/{shard}/features_entity_baseline',
    '{replica}'
)
ORDER BY (user_id, hostname, hour_of_day)
SETTINGS index_granularity = 256;
