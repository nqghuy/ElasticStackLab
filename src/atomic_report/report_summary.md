# Detection coverage report — Atomic Red Team vs Elastic Rules

## 1. Overview

- Total tests recorded: **247**
- Tests excluded due to execution failure: **22** (see `tables/failed_tests.csv`)
- Tests considered for detection stats: **225**
- Techniques tested: **47**
- Detected: **42** (18.7%)
- Undetected (including techniques with no rule): **183**
- Distinct rules triggered: **25**

## 2. Technique classification

- Not detected: **18** technique(s)
- Partially detected: **12** technique(s)
- No rule: **11** technique(s)
- Fully detected: **6** technique(s)

## 3. Top triggered rules

- Local Scheduled Task Creation: 21 time(s)
- Startup Persistence by a Suspicious Process: 21 time(s)
- Persistent Scripts in the Startup Directory: 12 time(s)
- Service Control Spawned via Script Interpreter: 5 time(s)
- Uncommon Registry Persistence Change: 5 time(s)
- Potential Application Shimming via Sdbinst: 4 time(s)
- Potential Persistence via Time Provider Modification: 4 time(s)
- User Account Creation: 4 time(s)
- Component Object Model Hijacking: 4 time(s)
- Startup or Run Key Registry Modification: 3 time(s)

## 4. Technique detail

| Technique   |   Tests detected |   Tests total |   Detection rate (%) | Status             | Has rule   |
|:------------|-----------------:|--------------:|---------------------:|:-------------------|:-----------|
| T1037.001   |                0 |             1 |                  0   | No rule            | No         |
| T1078.001   |                0 |             2 |                  0   | No rule            | No         |
| T1133       |                0 |             1 |                  0   | Not detected       | Yes        |
| T1136.002   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1137       |                0 |             1 |                  0   | Not detected       | Yes        |
| T1137.001   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1137.004   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1137.005   |                0 |             5 |                  0   | No rule            | No         |
| T1176       |                0 |             4 |                  0   | Not detected       | Yes        |
| T1505.003   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1505.004   |                0 |             2 |                  0   | No rule            | No         |
| T1505.005   |                0 |             2 |                  0   | No rule            | No         |
| T1542.001   |                0 |             1 |                  0   | No rule            | No         |
| T1546.001   |                0 |             1 |                  0   | No rule            | No         |
| T1546.002   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1546.007   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1546.008   |                0 |             8 |                  0   | Not detected       | Yes        |
| T1546.010   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1546.013   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1546.018   |                0 |             2 |                  0   | No rule            | No         |
| T1547       |                0 |             3 |                  0   | Not detected       | Yes        |
| T1547.004   |                0 |             4 |                  0   | Not detected       | Yes        |
| T1547.008   |                0 |             1 |                  0   | No rule            | No         |
| T1547.009   |                0 |             2 |                  0   | Not detected       | Yes        |
| T1547.010   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1547.012   |                0 |             1 |                  0   | Not detected       | Yes        |
| T1547.014   |                0 |             3 |                  0   | Not detected       | Yes        |
| T1556.001   |                0 |             1 |                  0   | No rule            | No         |
| T1556.002   |                0 |             2 |                  0   | No rule            | No         |
| T1112       |                7 |            87 |                  8   | Partially detected | Yes        |
| T1098       |                1 |            10 |                 10   | Partially detected | Yes        |
| T1543.003   |                1 |             5 |                 20   | Partially detected | Yes        |
| T1546       |                2 |             9 |                 22.2 | Partially detected | Yes        |
| T1078.003   |                1 |             4 |                 25   | Partially detected | Yes        |
| T1546.015   |                1 |             4 |                 25   | Partially detected | Yes        |
| T1546.003   |                1 |             3 |                 33.3 | Partially detected | Yes        |
| T1546.011   |                1 |             3 |                 33.3 | Partially detected | Yes        |
| T1547.001   |                9 |            19 |                 47.4 | Partially detected | Yes        |
| T1136.001   |                2 |             4 |                 50   | Partially detected | Yes        |
| T1547.005   |                1 |             2 |                 50   | Partially detected | Yes        |
| T1053.005   |                6 |            10 |                 60   | Partially detected | Yes        |
| T1197       |                1 |             1 |                100   | Fully detected     | Yes        |
| T1505.002   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.009   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.012   |                3 |             3 |                100   | Fully detected     | Yes        |
| T1547.002   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1547.003   |                2 |             2 |                100   | Fully detected     | Yes        |

## 5. Failed tests (excluded from stats above)

- T1053.005 test 3 (exit code 1): ERROR: No mapping between account names and security IDs was done.
- T1053.005 test 10 (exit code 1): The filename, directory name, or volume label syntax is incorrect.
- T1543.003 test 1 (exit code 1053): The service did not respond to the start or control request in a timely fashion.
- T1137.006 test 1: unknown error
- T1137.006 test 2: unknown error
- T1137.006 test 3: unknown error
- T1137.006 test 4: unknown error
- T1137.006 test 5: unknown error
- T1112 test 43 (exit code 1): Type "REG ADD /?" for usage.
- T1112 test 56 (exit code 1): ERROR: Access is denied.
- T1112 test 69: unknown error
- T1547.004 test 3: unknown error
- T1546.008 test 3 (exit code 1): The system cannot find the file specified.
- T1546.008 test 4 (exit code 1): The operation completed successfully.
- T1136.002 test 1 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1136.002 test 2 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1547.001 test 6: unknown error
- T1197 test 1 (exit code -2147023651): Unable to add file - 0x800704dd
- T1197 test 3 (exit code 1): Use the job identifier instead of the job name.
- T1197 test 4 (exit code -1): Executing test: T1197-4 Bits download using desktopimgdownldr.exe (cmd)
- T1137.002 test 1: unknown error
- T1053.002 test 1 (exit code 1): The request is not supported.

## Attached files

- `charts/01_overview_donut.png`
- `charts/02_technique_status_bar.png`
- `charts/03_top_rules_bar.png`
- `charts/04_technique_heatmap.png`
- `charts/04b_technique_heatmap_rotated.png`
- `tables/technique_detail.csv`
- `tables/rule_frequency.csv`
- `tables/failed_tests.csv`