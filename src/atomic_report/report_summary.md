# Detection coverage report — Atomic Red Team vs Elastic Rules

## 1. Overview

- Total tests recorded: **247**
- Tests excluded (execution failed, no alert produced): **14** (see `tables/failed_tests.csv`)
- Tests that failed to run but still produced an alert - **counted, not excluded**: **4** (see `tables/failed_but_counted.csv`)
- Tests considered for detection stats: **233**
- Techniques tested: **50**
- Detected: **49** (21.0%)
- Undetected (including techniques with no rule): **184**
- Distinct rules triggered: **27**

## 2. Technique classification

- Not detected: **20** technique(s)
- Partially detected: **11** technique(s)
- No rule: **11** technique(s)
- Fully detected: **7** technique(s)
- All tests failed: **1** technique(s)

## 3. Top triggered rules

- Local Scheduled Task Creation: 27 time(s)
- Startup Persistence by a Suspicious Process: 20 time(s)
- Service Control Spawned via Script Interpreter: 14 time(s)
- Bitsadmin Activity: 14 time(s)
- Persistence via Microsoft Office AddIns: 13 time(s)
- Persistent Scripts in the Startup Directory: 11 time(s)
- Service Path Modification via sc.exe: 6 time(s)
- Uncommon Registry Persistence Change: 6 time(s)
- Potential Persistence via Time Provider Modification: 4 time(s)
- Component Object Model Hijacking: 4 time(s)

## 4. Technique detail

| Technique   |   Tests detected |   Tests total |   Failed tests |   Detection rate (%) | Status             | Has rule   |
|:------------|-----------------:|--------------:|---------------:|---------------------:|:-------------------|:-----------|
| T1037.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1053.002   |                0 |             0 |              1 |                  0   | All tests failed   | Yes        |
| T1078.001   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1133       |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1136.001   |                0 |             4 |              0 |                  0   | Not detected       | Yes        |
| T1136.002   |                0 |             1 |              2 |                  0   | Not detected       | Yes        |
| T1137.001   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1137.002   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1137.005   |                0 |             5 |              0 |                  0   | No rule            | No         |
| T1176       |                0 |             4 |              0 |                  0   | Not detected       | Yes        |
| T1505.003   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1505.004   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1505.005   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1542.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1546.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1546.002   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1546.007   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1546.008   |                0 |             8 |              2 |                  0   | Not detected       | Yes        |
| T1546.009   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1546.011   |                0 |             3 |              0 |                  0   | Not detected       | Yes        |
| T1546.013   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1546.018   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1547       |                0 |             3 |              0 |                  0   | Not detected       | Yes        |
| T1547.002   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1547.004   |                0 |             4 |              1 |                  0   | Not detected       | Yes        |
| T1547.005   |                0 |             2 |              0 |                  0   | Not detected       | Yes        |
| T1547.008   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1547.010   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1547.012   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1547.014   |                0 |             3 |              0 |                  0   | Not detected       | Yes        |
| T1556.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1556.002   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1112       |                6 |            86 |              4 |                  7   | Partially detected | Yes        |
| T1098       |                1 |            10 |              0 |                 10   | Partially detected | Yes        |
| T1546       |                2 |             9 |              0 |                 22.2 | Partially detected | Yes        |
| T1078.003   |                1 |             4 |              0 |                 25   | Partially detected | Yes        |
| T1546.015   |                1 |             4 |              0 |                 25   | Partially detected | Yes        |
| T1547.001   |                9 |            19 |              1 |                 47.4 | Partially detected | Yes        |
| T1547.009   |                1 |             2 |              0 |                 50   | Partially detected | Yes        |
| T1053.005   |                7 |            11 |              1 |                 63.6 | Partially detected | Yes        |
| T1543.003   |                4 |             6 |              0 |                 66.7 | Partially detected | Yes        |
| T1546.012   |                2 |             3 |              0 |                 66.7 | Partially detected | Yes        |
| T1137.006   |                4 |             5 |              0 |                 80   | Partially detected | Yes        |
| T1137       |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.004   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1197       |                3 |             3 |              1 |                100   | Fully detected     | Yes        |
| T1505.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.003   |                2 |             2 |              1 |                100   | Fully detected     | Yes        |
| T1546.010   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.003   |                2 |             2 |              0 |                100   | Fully detected     | Yes        |

## 5. Failed tests, excluded (no alert produced)

- T1053.005 test 10 (exit code 1): The filename, directory name, or volume label syntax is incorrect.
- T1112 test 42 (exit code 1): ERROR: The system was unable to find the specified registry key or value.
- T1112 test 43 (exit code 1): Type "REG ADD /?" for usage.
- T1112 test 56 (exit code 1): ERROR: Access is denied.
- T1112 test 69: unknown error
- T1547.004 test 3: unknown error
- T1546.008 test 3 (exit code 1): The system cannot find the file specified.
- T1546.008 test 4 (exit code 1): The operation completed successfully.
- T1136.002 test 1 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1136.002 test 2 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1546.003 test 1: unknown error
- T1547.001 test 6: unknown error
- T1197 test 4 (exit code -1): Executing test: T1197-4 Bits download using desktopimgdownldr.exe (cmd)
- T1053.002 test 1 (exit code 1): The request is not supported.

## 5b. Failed tests, still counted (alert was produced)

- T1053.005 test 3 (exit code 1): ERROR: No mapping between account names and security IDs was done.
- T1543.003 test 1 (exit code 1053): The service did not respond to the start or control request in a timely fashion.
- T1197 test 1 (exit code -2147023651): Unable to add file - 0x800704dd
- T1197 test 3 (exit code 1): Use the job identifier instead of the job name.

## Attached files

- `charts/01_overview_donut.png`
- `charts/02_technique_status_bar.png`
- `charts/03_top_rules_bar.png`
- `charts/04_technique_heatmap.png`
- `tables/technique_detail.csv`
- `tables/rule_frequency.csv`
- `tables/failed_tests.csv`
- `tables/failed_but_counted.csv`