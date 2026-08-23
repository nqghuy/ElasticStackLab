# Detection coverage report — Atomic Red Team vs Elastic Rules

## 1. Overview

- Total tests recorded: **247**
- Tests excluded (execution failed, no alert produced): **13** (see `tables/failed_tests.csv`)
- Tests that failed to run but still produced an alert - **counted, not excluded**: **5** (see `tables/failed_but_counted.csv`)
- Tests considered for detection stats: **234**
- Techniques tested: **50**
- Detected: **70** (29.9%)
- Undetected (including techniques with no rule): **164**
- Distinct rules triggered: **39**

## 2. Technique classification

- Partially detected: **14** technique(s)
- Fully detected: **14** technique(s)
- No rule: **11** technique(s)
- Not detected: **10** technique(s)
- All tests failed: **1** technique(s)

## 3. Top triggered rules

- Local Scheduled Task Creation: 36 time(s)
- Bitsadmin Activity: 30 time(s)
- Startup Persistence by a Suspicious Process: 26 time(s)
- Service Control Spawned via Script Interpreter: 18 time(s)
- Persistent Scripts in the Startup Directory: 16 time(s)
- Persistence via Microsoft Office AddIns: 14 time(s)
- Uncommon Registry Persistence Change: 13 time(s)
- User Account Creation: 12 time(s)
- Startup or Run Key Registry Modification: 8 time(s)
- Service Path Modification via sc.exe: 6 time(s)

## 4. Technique detail

| Technique   |   Tests detected |   Tests total |   Failed tests |   Detection rate (%) | Status             | Has rule   |
|:------------|-----------------:|--------------:|---------------:|---------------------:|:-------------------|:-----------|
| T1037.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1053.002   |                0 |             0 |              1 |                  0   | All tests failed   | Yes        |
| T1078.001   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1133       |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1137.001   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1137.005   |                0 |             5 |              0 |                  0   | No rule            | No         |
| T1176       |                0 |             3 |              1 |                  0   | Not detected       | Yes        |
| T1505.003   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1505.004   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1505.005   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1542.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1546.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1546.002   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1546.008   |                0 |             8 |              2 |                  0   | Not detected       | Yes        |
| T1546.018   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1547       |                0 |             3 |              0 |                  0   | Not detected       | Yes        |
| T1547.004   |                0 |             4 |              1 |                  0   | Not detected       | Yes        |
| T1547.008   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1547.010   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1547.014   |                0 |             3 |              0 |                  0   | Not detected       | Yes        |
| T1556.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1556.002   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1098       |                1 |            10 |              0 |                 10   | Partially detected | Yes        |
| T1112       |                9 |            87 |              3 |                 10.3 | Partially detected | Yes        |
| T1546       |                2 |             9 |              0 |                 22.2 | Partially detected | Yes        |
| T1078.003   |                1 |             4 |              0 |                 25   | Partially detected | Yes        |
| T1546.015   |                1 |             4 |              0 |                 25   | Partially detected | Yes        |
| T1546.011   |                1 |             3 |              0 |                 33.3 | Partially detected | Yes        |
| T1136.001   |                2 |             4 |              0 |                 50   | Partially detected | Yes        |
| T1547.005   |                1 |             2 |              0 |                 50   | Partially detected | Yes        |
| T1547.009   |                1 |             2 |              0 |                 50   | Partially detected | Yes        |
| T1053.005   |                7 |            11 |              1 |                 63.6 | Partially detected | Yes        |
| T1136.002   |                2 |             3 |              0 |                 66.7 | Partially detected | Yes        |
| T1543.003   |                4 |             6 |              0 |                 66.7 | Partially detected | Yes        |
| T1137.006   |                3 |             4 |              1 |                 75   | Partially detected | Yes        |
| T1547.001   |               15 |            19 |              1 |                 78.9 | Partially detected | Yes        |
| T1137       |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.004   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1197       |                3 |             3 |              1 |                100   | Fully detected     | Yes        |
| T1505.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.003   |                2 |             2 |              1 |                100   | Fully detected     | Yes        |
| T1546.007   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.009   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.010   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.012   |                3 |             3 |              0 |                100   | Fully detected     | Yes        |
| T1546.013   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.003   |                2 |             2 |              0 |                100   | Fully detected     | Yes        |
| T1547.012   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |

## 5. Failed tests, excluded (no alert produced)

- T1053.005 test 10 (exit code 1): The filename, directory name, or volume label syntax is incorrect.
- T1137.006 test 5: unknown error
- T1176 test 4: unknown error
- T1112 test 43 (exit code 1): Type "REG ADD /?" for usage.
- T1112 test 56 (exit code 1): ERROR: Access is denied.
- T1112 test 69: unknown error
- T1547.004 test 3: unknown error
- T1546.008 test 3 (exit code 1): The system cannot find the file specified.
- T1546.008 test 4 (exit code 1): The operation completed successfully.
- T1546.003 test 1: unknown error
- T1547.001 test 6: unknown error
- T1197 test 4 (exit code -1): Executing test: T1197-4 Bits download using desktopimgdownldr.exe (cmd)
- T1053.002 test 1 (exit code 1): The request is not supported.

## 5b. Failed tests, still counted (alert was produced)

- T1053.005 test 3 (exit code 1): ERROR: No mapping between account names and security IDs was done.
- T1543.003 test 1 (exit code 1053): The service did not respond to the start or control request in a timely fashion.
- T1136.002 test 1 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1136.002 test 2 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1197 test 1 (exit code -2147023651): BITSADMIN version 3.0

## Attached files

- `charts/01_overview_donut.png`
- `charts/02_technique_status_bar.png`
- `charts/03_top_rules_bar.png`
- `charts/04_technique_heatmap.png`
- `tables/technique_detail.csv`
- `tables/rule_frequency.csv`
- `tables/failed_tests.csv`
- `tables/failed_but_counted.csv`