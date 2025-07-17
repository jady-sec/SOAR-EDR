# LaZagne Detection and Response Workflow

This project implements an automated Security Orchestration, Automation, and Response (SOAR) workflow for detecting and responding to LaZagne executions in an Endpoint Detection and Response (EDR) environment. LaZagne is a credential-dumping tool often used in attacks, so we detect it via LimaCharlie (EDR), enrich with VirusTotal, notify via Slack with interactive buttons (Quarantine/Ignore), and automate responses in Tines (SOAR tool).

The workflow ensures only one detection per execution (via suppression), handles duplicates, quarantines machines on approval, deletes alerts on ignore, and sends confirmations.

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Setup Guide](#setup-guide)
  - [LimaCharlie Configuration](#limacharlie-configuration)
  - [Tines Workflow](#tines-workflow)
  - [Slack App Integration](#slack-app-integration)
  - [VirusTotal Integration](#virustotal-integration)
- [Testing and Troubleshooting](#testing-and-troubleshooting)
- [Extensions and Improvements](#extensions-and-improvements)
- [License](#license)

## Overview
The system detects LaZagne runs on Windows endpoints, sends alerts to Slack for analyst review, and automates quarantine (network isolation) or ignore actions. Key features:
- Deduplication to avoid multiple alerts per execution.
- Enrichment with VirusTotal for threat intel.
- Interactive Slack buttons for quick response.
- Email/Slack confirmations post-action.
- Secure API handling with credentials.

**Why this project?** It demonstrates EDR-SOAR integration for faster incident response, reducing manual work.

[Screenshot Suggestion: Insert a high-level flow diagram here (use tools like Draw.io or Lucidchart to create one showing LimaCharlie → Webhook → Tines → VirusTotal → Slack → Back to Tines/LimaCharlie). Label components and arrows with steps.]

## Architecture
The workflow:
1. LimaCharlie detects LaZagne via D&R rule (NEW_PROCESS/EXISTING_PROCESS events).
2. Webhook sends detection to Tines.
3. Tines enriches with VirusTotal API.
4. Tines posts interactive Slack message with details and buttons (Quarantine/Ignore).
5. On button click:
   - Quarantine: Extracts sid, fetches JWT, isolates via LimaCharlie API, deletes alert, sends confirmation.
   - Ignore: Deletes alert, sends "Marked as false positive" message.
6. Suppress duplicates in LimaCharlie rule.

[Screenshot Suggestion: Include a screenshot of the full Tines storyboard canvas showing agents connected (webhook, parse, branch/Trigger, extraction, isolation, delete, confirmation). Blur sensitive parts like keys.]

## Prerequisites
- **LimaCharlie Account**: With API key (user-scoped with "sensor:isolate" permission) and UID/OID.
- **Tines Account**: Free tier works; create credentials for APIs.
- **Slack Workspace**: App with bot token (scopes: chat:write, chat:delete, incoming-webhooks).
- **VirusTotal API Key**: Free account for enrichment.
- Test endpoint (Windows VM) with LaZagne.exe for testing.

## Setup Guide

### LimaCharlie Configuration
1. Log into app.limacharlie.io > Detection & Response > Rules > Create Rule.
2. Use this YAML for detection (matches file path, command line, or hash; Windows only):
   ```yaml
   detect:
     events:
       - NEW_PROCESS
       - EXISTING_PROCESS
     op: and
     rules:
       - op: is windows
       - op: or
         rules:
           - case sensitive: false
             op: ends with
             path: event/FILE_PATH
             value: LaZagne.exe
           - case sensitive: false
             op: contains
             path: event/COMMAND_LINE
             value: Lazagne
           - case sensitive: false
             op: is
             path: event/HASH
             value: 64dd55e1c2373deed25c2776f553c632e58c45e56a0e4639dfd54ee97eab9c19
