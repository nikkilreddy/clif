CREATE DATABASE IF NOT EXISTS clif_logs;

CREATE TABLE IF NOT EXISTS clif_logs.raw_logs (
  event_id UUID, timestamp DateTime64(3), received_at DateTime64(3), level LowCardinality(String), source LowCardinality(String), message String,
  metadata Map(String, String), user_id String, ip_address IPv4, request_id String, anchor_tx_id String, anchor_batch_hash String
) ENGINE = MergeTree ORDER BY (timestamp, event_id);

CREATE TABLE IF NOT EXISTS clif_logs.security_events (
  event_id UUID, timestamp DateTime64(3), severity UInt8, category LowCardinality(String), source LowCardinality(String), description String,
  user_id String, ip_address IPv4, hostname String, mitre_tactic LowCardinality(String), mitre_technique LowCardinality(String),
  ai_confidence Float32, ai_explanation String, anchor_tx_id String, metadata Map(String, String)
) ENGINE = MergeTree ORDER BY (timestamp, event_id);

CREATE TABLE IF NOT EXISTS clif_logs.process_events (
  event_id UUID, timestamp DateTime64(3), hostname String, pid Int64, ppid Int64, uid Int64, gid Int64, binary_path String, arguments String,
  cwd String, exit_code Int64, container_id String, pod_name String, namespace String, syscall String, is_suspicious UInt8, detection_rule String,
  anchor_tx_id String, metadata Map(String, String)
) ENGINE = MergeTree ORDER BY (timestamp, event_id);

CREATE TABLE IF NOT EXISTS clif_logs.network_events (
  event_id UUID, timestamp DateTime64(3), hostname String, src_ip IPv4, src_port UInt16, dst_ip IPv4, dst_port UInt16, protocol String,
  direction String, bytes_sent UInt64, bytes_received UInt64, duration_ms UInt64, pid Int64, binary_path String, container_id String,
  pod_name String, namespace String, dns_query String, geo_country String, is_suspicious UInt8, detection_rule String, anchor_tx_id String,
  metadata Map(String, String)
) ENGINE = MergeTree ORDER BY (timestamp, event_id);

CREATE TABLE IF NOT EXISTS clif_logs.triage_scores (
  score_id UUID DEFAULT generateUUIDv4(), event_id UUID, timestamp DateTime64(3), source_type LowCardinality(String), hostname String,
  source_ip String, user_id String, template_id String, template_rarity Float32, combined_score Float32, lgbm_score Float32, eif_score Float32,
  arf_score Float32, score_std_dev Float32, agreement Float32, ci_lower Float32, ci_upper Float32, asset_multiplier Float32, adjusted_score Float32,
  action Enum8('discard' = 0, 'monitor' = 1, 'escalate' = 2), ioc_match UInt8, ioc_confidence UInt8, mitre_tactic String,
  mitre_technique String, shap_top_features String, shap_summary String, features_stale UInt8, model_version String, disagreement_flag UInt8
) ENGINE = MergeTree ORDER BY (timestamp, event_id);

CREATE TABLE IF NOT EXISTS clif_logs.hunter_investigations (
  investigation_id UUID DEFAULT generateUUIDv4(), alert_id UUID, started_at DateTime64(3), completed_at Nullable(DateTime64(3)),
  status Enum8('pending' = 0, 'running' = 1, 'completed' = 2, 'failed' = 3, 'timeout' = 4), hostname String, source_ip String, user_id String,
  trigger_score Float32, severity Enum8('info' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4), finding_type String, summary String,
  evidence_json String, correlated_events Array(UUID), mitre_tactics Array(String), mitre_techniques Array(String), recommended_action String,
  confidence Float32
) ENGINE = MergeTree ORDER BY (started_at, investigation_id);

CREATE TABLE IF NOT EXISTS clif_logs.verifier_results (
  verification_id UUID DEFAULT generateUUIDv4(), investigation_id UUID, alert_id UUID, started_at DateTime64(3), completed_at Nullable(DateTime64(3)),
  status Enum8('pending' = 0, 'running' = 1, 'verified' = 2, 'false_positive' = 3, 'inconclusive' = 4, 'failed' = 5),
  verdict Enum8('true_positive' = 0, 'false_positive' = 1, 'inconclusive' = 2), confidence Float32, evidence_verified UInt8, merkle_batch_ids Array(String),
  timeline_json String, ioc_correlations String, priority Enum8('P1' = 1, 'P2' = 2, 'P3' = 3, 'P4' = 4), recommended_action String,
  analyst_summary String, report_narrative String, evidence_json String
) ENGINE = MergeTree ORDER BY (started_at, verification_id);

CREATE TABLE IF NOT EXISTS clif_logs.feedback_labels (
  event_id UUID, score_id Nullable(UUID), timestamp DateTime64(3), label LowCardinality(String), confidence LowCardinality(String),
  analyst_id String, notes String, original_combined Float32, original_lgbm Float32, original_eif Float32, original_arf Float32
) ENGINE = MergeTree ORDER BY (timestamp, event_id);

CREATE TABLE IF NOT EXISTS clif_logs.evidence_anchors (
  batch_id String, merkle_root String, event_count UInt64, time_from DateTime64(3), time_to DateTime64(3), prev_merkle_root String, table_name String
) ENGINE = MergeTree ORDER BY (time_from, batch_id);

CREATE TABLE IF NOT EXISTS clif_logs.security_severity_hourly (
  hour DateTime, severity UInt8, cnt UInt64, event_count UInt64
) ENGINE = SummingMergeTree ORDER BY (hour, severity);
