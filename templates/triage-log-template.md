# SOC Alert Triage Log

## Alert #1
**Date:** 2026-01-10  
**Alert Title:** Brute Force Attempt Detected  
**Severity:** High  
**Source IP:** 203.0.113.45 (external)  
**Target:** user@company.com  

**Hypothesis:** External attacker attempting credential stuffing  

**Evidence:**
- 150 failed login attempts in 5 minutes
- Source IP flagged on AbuseIPDB (malicious score: 85%)
- No successful logins

**Classification:** True Positive - Malicious  
**Action Taken:** Blocked source IP, recommended MFA enforcement  
**Time to Triage:** 8 minutes  

---

## Alert #2
[Repeat for all alerts...]