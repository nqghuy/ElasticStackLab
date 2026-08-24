# Detection coverage report — Atomic Red Team vs Elastic Rules

## 1. Overview

- Total tests recorded: **247**
- Tests excluded (execution failed, no alert produced): **31** (see `tables/failed_tests.csv`)
- Tests that failed to run but still produced an alert - **counted, not excluded**: **9** (see `tables/failed_but_counted.csv`)
- Tests considered for detection stats: **216**
- Techniques tested: **50**
- Detected: **70** (32.4%)
- Undetected (including techniques with no rule): **146**
- Distinct rules triggered: **39**

## 2. Technique classification

- Fully detected: **17** technique(s)
- Partially detected: **11** technique(s)
- No rule: **11** technique(s)
- Not detected: **9** technique(s)
- All tests failed: **2** technique(s)

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
| T1053.005   |                7 |            11 |              1 |                 63.6 | Partially detected | Yes        |
| T1078.001   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1078.003   |                1 |             2 |              2 |                 50   | Partially detected | Yes        |
| T1098       |                1 |             1 |              9 |                100   | Fully detected     | Yes        |
| T1112       |                9 |            85 |              5 |                 10.6 | Partially detected | Yes        |
| T1133       |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1136.001   |                2 |             4 |              0 |                 50   | Partially detected | Yes        |
| T1136.002   |                2 |             2 |              1 |                100   | Fully detected     | Yes        |
| T1137       |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.001   |                0 |             0 |              1 |                  0   | All tests failed   | Yes        |
| T1137.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.004   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.005   |                0 |             5 |              0 |                  0   | No rule            | No         |
| T1137.006   |                3 |             4 |              1 |                 75   | Partially detected | Yes        |
| T1176       |                0 |             3 |              1 |                  0   | Not detected       | Yes        |
| T1197       |                3 |             3 |              1 |                100   | Fully detected     | Yes        |
| T1505.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1505.003   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1505.004   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1505.005   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1542.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1543.003   |                4 |             5 |              1 |                 80   | Partially detected | Yes        |
| T1546       |                2 |             8 |              1 |                 25   | Partially detected | Yes        |
| T1546.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1546.002   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1546.003   |                2 |             2 |              1 |                100   | Fully detected     | Yes        |
| T1546.007   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.008   |                0 |             8 |              2 |                  0   | Not detected       | Yes        |
| T1546.009   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.010   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.011   |                1 |             3 |              0 |                 33.3 | Partially detected | Yes        |
| T1546.012   |                3 |             3 |              0 |                100   | Fully detected     | Yes        |
| T1546.013   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.015   |                1 |             4 |              0 |                 25   | Partially detected | Yes        |
| T1546.018   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1547       |                0 |             3 |              0 |                  0   | Not detected       | Yes        |
| T1547.001   |               15 |            19 |              1 |                 78.9 | Partially detected | Yes        |
| T1547.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.003   |                2 |             2 |              0 |                100   | Fully detected     | Yes        |
| T1547.004   |                0 |             4 |              1 |                  0   | Not detected       | Yes        |
| T1547.005   |                1 |             1 |              1 |                100   | Fully detected     | Yes        |
| T1547.008   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1547.009   |                1 |             2 |              0 |                 50   | Partially detected | Yes        |
| T1547.010   |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1547.012   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.014   |                0 |             3 |              0 |                  0   | Not detected       | Yes        |
| T1556.001   |                0 |             1 |              0 |                  0   | No rule            | No         |
| T1556.002   |                0 |             2 |              0 |                  0   | No rule            | No         |

## 5. Failed tests, excluded (no alert produced)

- T1053.005 test 10 (exit code 1): The filename, directory name, or volume label syntax is incorrect.
- T1543.003 test 6: set-servicebinarypath : The term 'set-servicebinarypath' is not recognized as the name of a cmdlet, function, script
- T1137.006 test 5: unknown error
- T1176 test 4: unknown error
- T1547.005 test 2: + CategoryInfo          : InvalidArgument: (Security Packages:String) [Get-ItemProperty], PSArgumentException
- T1112 test 7: + CategoryInfo          : ObjectNotFound: (Set-ExecutionPolicy:String) [], CommandNotFoundException
- T1112 test 11: New-ItemProperty : Cannot find path 'HKCU:\Software\Policies\Microsoft\Windows\System' because it does not exist.
- T1112 test 43 (exit code 1): ERROR: Invalid syntax.
- T1112 test 56 (exit code 1): ERROR: Access is denied.
- T1112 test 69: unknown error
- T1547.004 test 3: unknown error
- T1546.008 test 3 (exit code 1): The system cannot find the file specified.
- T1546.008 test 4 (exit code 1): The operation completed successfully.
- T1136.002 test 3: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1137.001 test 1: + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
- T1546.003 test 1: unknown error
- T1547.001 test 6: unknown error
- T1098 test 2: New-ADUser : Unable to find a default server with Active Directory Web Services running.
- T1098 test 9: Synchronizing password failed. Verify that
- T1098 test 10: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1098 test 11: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1098 test 12: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1098 test 13: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1098 test 14: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1098 test 15: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1098 test 16: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1546 test 4: + CategoryInfo          : ObjectNotFound: (ConvertTo-SecureString:String) [], CommandNotFoundException
- T1197 test 4 (exit code -1): Executing test: T1197-4 Bits download using desktopimgdownldr.exe (cmd)
- T1053.002 test 1 (exit code 1): The request is not supported.
- T1078.003 test 6: Exception calling "DownloadString" with "1" argument(s): "Could not find a part of the path
- T1078.003 test 7: Exception calling "DownloadString" with "1" argument(s): "Could not find a part of the path

## 5b. Failed tests, still counted (alert was produced)

- T1053.005 test 3 (exit code 1): ERROR: No mapping between account names and security IDs was done.
- T1543.003 test 1 (exit code 1053): [SC] StartService FAILED 1053:
- T1505.002 test 1: Install-TransportAgent : The term 'Install-TransportAgent' is not recognized as the name of a cmdlet, function, script
- T1136.002 test 1 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1136.002 test 2 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1547.001 test 14: + CategoryInfo          : InvalidArgument: (:) [Get-ItemPropertyValue], PSArgumentException
- T1547.001 test 15: + CategoryInfo          : InvalidArgument: (:) [Get-ItemPropertyValue], PSArgumentException
- T1197 test 1 (exit code -2147023651): BITSADMIN version 3.0
- T1197 test 2: network. The specified service does not exist. (Exception from HRESULT: 0x800704DD)

## Attached files

- `charts/01_overview_donut.png`
- `charts/02_technique_status_bar.png`
- `charts/03_top_rules_bar.png`
- `charts/04_technique_heatmap.png`
- `tables/technique_detail.csv`
- `tables/rule_frequency.csv`
- `tables/failed_tests.csv`
- `tables/failed_but_counted.csv`