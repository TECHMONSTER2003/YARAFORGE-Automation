# yaraforge report - MockBot

Samples: 8 | Goodware: 99 | Runtime: 127.0s

## Rule evaluation

| Rule | TP | FN | FP | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| MockBot_Strings | 8 | 0 | 0 | 99 | 1.000 | 1.000 | 1.000 | 0.0000 |
| MockBot_Imports_Baseline | 8 | 0 | 2 | 97 | 0.800 | 1.000 | 0.889 | 0.0202 |

## Leave-one-out: 8/8 held-out samples detected

| Held-out | Detected | Matched | Goodware FP |
|---|---|---|---|
| mockbot_v2_a.exe | yes | 6/6 | 0 |
| mockbot_v2_b.exe | yes | 6/6 | 0 |
| mockbot_v2_c.exe | yes | 6/6 | 0 |
| mockbot_v2_d.exe | yes | 6/6 | 0 |
| mockbot_v2_e.exe | yes | 5/6 | 0 |
| mockbot_v2_f.exe | yes | 6/6 | 0 |
| mockbot_v2_g.exe | yes | 6/6 | 0 |
| mockbot_v3_drift.exe | yes | 4/6 | 0 |

## Selected strings

| Score | Coverage | Source | IOC | Value |
|---|---|---|---|---|
| 1.000 | 1.00 | static | config_marker | `[MockBot harmless lab sample] cfg=%s tag=%s junk=%u` |
| 0.925 | 0.88 | static | user_agent | `Mozilla/4.0 (compatible; MkBot/2.1; lab)` |
| 0.912 | 1.00 | prefix | config_marker | `MKBCFG::v2::build=` |
| 0.844 | 0.88 | static | mutex | `Global\MkB_7f3a9c21` |
| 0.800 | 1.00 | static | - | `mutex=%d run=%d net=%d (no network activity performed)` |
| 0.700 | 0.50 | decoded | url | `http://c2.mockbot.invalid/gate.php?id=` |

## MITRE ATT&CK (capa)

| ID | Tactic | Technique | Coverage |
|---|---|---|---|
| T1071.001 | Command and Control | Application Layer Protocol: Web Protocols | 1.00 |
| T1027 | Defense Evasion | Obfuscated Files or Information | 1.00 |
| T1140 | Defense Evasion | Deobfuscate/Decode Files or Information | 1.00 |
| T1480 | Defense Evasion | Execution Guardrails | 1.00 |
| T1622 | Defense Evasion | Debugger Evasion | 1.00 |
| T1012 | Discovery | Query Registry | 1.00 |
| T1129 | Execution | Shared Modules | 0.38 |
| T1547.001 | Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | 1.00 |
