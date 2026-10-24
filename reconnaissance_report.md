# 🔍 Architectural Reconnaissance Report — Ghost Data Still Exists

## 1. Dataset Scale & Shape

| Asset | Rows / Files | Key Observations |
|---|---|---|
| `deletion_requests.csv` | **518 cases** (case_33 → case_550) | 254 COMPLETE, 152 PARTIALLY_COMPLETE, 112 NOT_STARTED reported |
| `sample_deletion_requests.csv` | 32 cases (case_01 → case_32) | Separate from the 518; golden answers in `sample_output.csv` |
| `sample_output.csv` | 32 rows | **10 COMPLETE, 22 INCOMPLETE, 0 NOT_APPLICABLE** in samples |
| `user_identities.csv` | **850 users** | user_id, name, email, phone, email_hash, updated_at |
| `user_audit_log.csv` | **306 identity changes** | 107 email changes, 107 email_hash changes, 92 phone changes |
| `system_activity.csv` | **4,011 events** | 17 event_types across 24 unique systems |
| `evidence_files.csv` | **94 evidence files** | evidence_01 → evidence_94 |
| Evidence directories | 26 SQL, 4 PDFs, 11 PNGs, 26 logs, 29 JSON/TXT records | Multi-modal: text, SQL, images, PDFs |

## 2. System Topology (24 Systems)

```
┌─────────────────────────────────────────────────────────────────┐
│                    CORE IDENTITY LAYER                          │
│  account_service │ identity_service │ profile_service           │
│  account_failover_replica │ account_replication_cluster         │
├─────────────────────────────────────────────────────────────────┤
│                    DATA PROCESSING                              │
│  analytics_platform │ search_service │ cache_service            │
│  marketing_platform │ export_service │ email_delivery_service   │
├─────────────────────────────────────────────────────────────────┤
│                    INTEGRATION & FLOW                           │
│  integration_service │ notification_service │ data_catalog      │
│  object_storage │ object_store                                  │
├─────────────────────────────────────────────────────────────────┤
│                    COMPLIANCE & RETENTION                       │
│  security_service │ legal_service │ archive_service             │
│  backup_service │ support_platform                              │
├─────────────────────────────────────────────────────────────────┤
│                    ORCHESTRATION                                │
│  deletion_worker │ privacy_case_management │ privacy_intake     │
└─────────────────────────────────────────────────────────────────┘
```

## 3. Deletion Rules Matrix (15 Rules)

| Rule | Category | Action | Key Implication |
|---|---|---|---|
| rule_01 | USER_PROFILE | **DELETE** | Account must be fully removed |
| rule_02 | SECONDARY_IDENTIFIER | **DELETE** | All secondary IDs must go |
| rule_03 | SEARCH_INDEX_ENTRY | **DELETE** | Search indexes must be purged |
| rule_04 | CACHE_ENTRY | **DELETE** | Caches must be cleared |
| rule_05 | SUPPORT_MESSAGE | **REDACT** | Keep conversation, strip PII |
| rule_06 | SUPPORT_ATTACHMENT | **DELETE** | Remove if belongs only to subject |
| rule_07 | ANALYTICS_PROFILE | **ANONYMIZE** | De-link from user, keep stats |
| rule_08 | PRODUCT_TELEMETRY | **ANONYMIZE** | De-link telemetry |
| rule_09 | USER_EXPORT | **DELETE** | Exports must be removed |
| rule_10 | MARKETING_PROFILE | **DELETE** | Marketing records must go |
| rule_11 | EMAIL_DELIVERY_LOG | **REDACT** | Redact email from logs |
| rule_12 | SECURITY_AUDIT_LOG | **RETAIN** | Keep within retention period |
| rule_13 | LEGAL_HOLD_RECORD | **RETAIN** | Keep if legal hold active |
| rule_14 | BACKUP_ARCHIVE | **RETAIN** | Keep backup but block restore |
| rule_15 | ACCOUNT_TOMBSTONE | **REDACT** | Keep user_id, strip all PII |

## 4. Critical Decision Taxonomy

### 4a. Status Decision Tree
```
request_text → Is it a deletion request?
    ├─ NO  → NOT_APPLICABLE (steps_json = [])
    │         ~6 cases: access/export/correction/opt-out/login-reset
    └─ YES → Resolve identities → Gather all evidence at audit_at
              ├─ All records compliant, no active flows/risks → COMPLETE
              │   Steps: VERIFICATION only (with evidence_id citations)
              └─ Any violations remain → INCOMPLETE
                  Steps: FINDING → REMEDIATION → VERIFICATION
                  Findings cite evidence; remediation/verification use evidence_id=""
```

### 4b. NOT_APPLICABLE Cases Identified (~6)
| Case | Request Type |
|---|---|
| case_533 | Phone number update |
| case_535 | Data portability/download |
| case_536 | Login reset, explicitly "do not close" |
| case_540 | Invoice copy request |
| case_541 | Email change |
| case_542 | Data access request, "don't delete" |

### 4c. Multi-Language Support Required
Requests in: English, Spanish, French, Korean (삭제), Japanese (削除), Portuguese (exclusão), German, and more. All non-English texts with deletion keywords → treat as valid deletion requests.

## 5. Evidence Architecture

### Evidence Types & Processing Needs
| Type | Count | Processing |
|---|---|---|
| **SQL snapshots** | 26 files | Parse INSERT statements, extract user records from tables (accounts, replicas, inventories, search indexes) |
| **JSON snapshots** | ~17 files | Parse structured data bundles, resource exports, connector configs, analytics, audit ledgers |
| **Log files** | 26 files | Parse structured/unstructured logs, extract events referencing users |
| **PNG screenshots** | 11 files | OCR/vision: admin consoles, profile views, backup consoles |
| **PDF documents** | 4 files | OCR/vision: retention registers, security extracts, delivery attachments, account history |
| **TXT records** | 1 file | Plain text handover records |

### Evidence Temporal Coverage
- Earliest: 2026-01-29 (service_resource_export)
- Latest: 2026-10-01 (security_audit_ledger, customer_account_handover)
- Monthly `service_resource_export` and `customer_data_inventory` snapshots provide periodic state views
- `resource_lookup_trace` logs provide periodic readback proofs

## Key Architectural Findings

> [!IMPORTANT]
> ### Finding 1: Evidence is Global, Not Per-Case
> The manifest does NOT link evidence to cases. The agent must match evidence to users via identifiers (email, user_id, phone, email_hash) found within the evidence content itself.

> [!IMPORTANT]
> ### Finding 2: Identity Resolution is Multi-Step
> Users change emails, phones, and email_hashes over time (306 audit entries). The request email may be historical. Must build a full identifier graph per user: current + all historical values.

> [!IMPORTANT]
> ### Finding 3: Sample Output Has No NOT_APPLICABLE
> All 32 sample cases are deletion requests. The ~6 NOT_APPLICABLE cases are only in the 518-case evaluation set, meaning we must handle them using NLP intent classification without ground truth examples.

> [!WARNING]
> ### Finding 4: Step Ordering is Deterministic
> The problem statement specifies: within each phase, order by operation (table order), then `system_id` ASC, then `resource_id` ASC. This is a strict lexicographic sort — not heuristic.

> [!WARNING]
> ### Finding 5: Evidence Citation Rules Differ by Status
> - **COMPLETE**: All verification steps MUST cite evidence (file_id, activity_id, or audit_id)
> - **INCOMPLETE**: Findings cite evidence; remediation + future verification use `evidence_id: ""`
