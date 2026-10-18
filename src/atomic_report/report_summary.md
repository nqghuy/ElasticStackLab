# Detection coverage report — Atomic Red Team vs Elastic Rules

## 1. Overview

- Total tests recorded: **247**
- Tests excluded (execution failed, no alert produced): **35** (see `tables/failed_tests.csv`)
- Tests that failed to run but still produced an alert - **counted, not excluded**: **19** (see `tables/failed_but_counted.csv`)
- Tests considered for detection stats: **212**
- Techniques tested: **50**
- Detected: **192** (90.6%)
- Undetected (including techniques with no rule): **20**
- Distinct rules triggered: **90**

## 2. Technique classification

- Fully detected: **36** technique(s)
- All tests failed: **7** technique(s)
- Partially detected: **4** technique(s)
- No rule: **2** technique(s)
- Not detected: **1** technique(s)

## 3. Top triggered rules

- Local Scheduled Task Creation: 36 time(s)
- Windows Explorer Functionality Restriction: 32 time(s)
- Startup Persistence by a Suspicious Process: 31 time(s)
- Modify user account: 28 time(s)
- Windows Policy Registry Modification: 22 time(s)
- Bitsadmin Activity: 22 time(s)
- Service Control Spawned via Script Interpreter: 18 time(s)
- Persistent Scripts in the Startup Directory: 18 time(s)
- Persistence via Microsoft Office AddIns: 15 time(s)
- Windows Registry Modification to Impair Security Controls or Visibility: 14 time(s)

## 4. Technique detail

| Technique   |   Tests detected |   Tests total |   Failed tests |   Detection rate (%) | Status             | Has rule   |
|:------------|-----------------:|--------------:|---------------:|---------------------:|:-------------------|:-----------|
| T1037.001   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1053.002   |                0 |             0 |              1 |                  0   | All tests failed   | Yes        |
| T1053.005   |               11 |            11 |              1 |                100   | Fully detected     | Yes        |
| T1078.001   |                2 |             2 |              0 |                100   | Fully detected     | Yes        |
| T1078.003   |                2 |             2 |              2 |                100   | Fully detected     | Yes        |
| T1098       |                1 |             1 |              9 |                100   | Fully detected     | Yes        |
| T1112       |               78 |            90 |              0 |                 86.7 | Partially detected | Yes        |
| T1133       |                0 |             1 |              0 |                  0   | Not detected       | Yes        |
| T1136.001   |                4 |             4 |              0 |                100   | Fully detected     | Yes        |
| T1136.002   |                2 |             2 |              1 |                100   | Fully detected     | Yes        |
| T1137       |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.001   |                0 |             0 |              1 |                  0   | All tests failed   | Yes        |
| T1137.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.004   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1137.005   |                0 |             0 |              5 |                  0   | All tests failed   | No         |
| T1137.006   |                5 |             5 |              0 |                100   | Fully detected     | Yes        |
| T1176       |                0 |             0 |              4 |                  0   | All tests failed   | Yes        |
| T1197       |                3 |             3 |              1 |                100   | Fully detected     | Yes        |
| T1505.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1505.003   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1505.004   |                0 |             0 |              2 |                  0   | All tests failed   | No         |
| T1505.005   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1542.001   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1543.003   |                4 |             5 |              1 |                 80   | Partially detected | Yes        |
| T1546       |                8 |             8 |              1 |                100   | Fully detected     | Yes        |
| T1546.001   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.003   |                2 |             2 |              1 |                100   | Fully detected     | Yes        |
| T1546.007   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.008   |                9 |             9 |              1 |                100   | Fully detected     | Yes        |
| T1546.009   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.010   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.011   |                3 |             3 |              0 |                100   | Fully detected     | Yes        |
| T1546.012   |                3 |             3 |              0 |                100   | Fully detected     | Yes        |
| T1546.013   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1546.015   |                4 |             4 |              0 |                100   | Fully detected     | Yes        |
| T1546.018   |                0 |             2 |              0 |                  0   | No rule            | No         |
| T1547       |                3 |             3 |              0 |                100   | Fully detected     | Yes        |
| T1547.001   |               20 |            20 |              0 |                100   | Fully detected     | Yes        |
| T1547.002   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.003   |                2 |             2 |              0 |                100   | Fully detected     | Yes        |
| T1547.004   |                4 |             5 |              0 |                 80   | Partially detected | Yes        |
| T1547.005   |                1 |             1 |              1 |                100   | Fully detected     | Yes        |
| T1547.008   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.009   |                2 |             2 |              0 |                100   | Fully detected     | Yes        |
| T1547.010   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.012   |                1 |             1 |              0 |                100   | Fully detected     | Yes        |
| T1547.014   |                2 |             3 |              0 |                 66.7 | Partially detected | Yes        |
| T1556.001   |                0 |             0 |              1 |                  0   | All tests failed   | Yes        |
| T1556.002   |                0 |             0 |              2 |                  0   | All tests failed   | Yes        |

## 5. Failed tests, excluded (no alert produced)

- T1053.005 test 10 (exit code 1): The filename, directory name, or volume label syntax is incorrect.
- T1543.003 test 6: set-servicebinarypath : The term 'set-servicebinarypath' is not recognized as the name of a cmdlet, function, script
- T1556.002 test 1 (exit code -1): Process Timed out after 100 seconds, use '-TimeoutSeconds' to specify a different timeout
- T1556.002 test 2 (exit code -1): Process Timed out after 100 seconds, use '-TimeoutSeconds' to specify a different timeout
- T1176 test 1: Found 0 atomic tests applicable to windows platform for Technique T1176
- T1176 test 2: Found 0 atomic tests applicable to windows platform for Technique T1176
- T1176 test 3: Found 0 atomic tests applicable to windows platform for Technique T1176
- T1176 test 4 (exit code -1): Exception calling "ExtractToFile" with "3" argument(s): "There is not enough space on the disk.
- T1137.005 test 1 (exit code 1): Outlook COM fails with 0x80080005 when run as Administrator.
- T1137.005 test 2 (exit code 1): Outlook COM fails with 0x80080005 when run as Administrator.
- T1137.005 test 3 (exit code 1): Outlook COM fails with 0x80080005 when run as Administrator.
- T1137.005 test 4 (exit code 1): Outlook COM fails with 0x80080005 when run as Administrator.
- T1137.005 test 5 (exit code 1): Outlook COM fails with 0x80080005 when run as Administrator.
- T1547.005 test 2: + CategoryInfo          : InvalidArgument: (Security Packages:String) [Get-ItemProperty], PSArgumentException
- T1546.008 test 3 (exit code 1): The system cannot find the file specified.
- T1136.002 test 3: New-Object : Exception calling ".ctor" with "1" argument(s): "The server could not be contacted."
- T1137.001 test 1: + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
- T1546.003 test 1: + CategoryInfo          : ResourceExists: (__EventFilter:CimInstance) [New-CimInstance], CimException
- T1098 test 2: New-ADUser : Unable to find a default server with Active Directory Web Services running.
- T1098 test 9: Synchronizing password failed. Verify that
- T1098 test 10 (exit code 1355): Unable to find a default server with Active Directory Web Services running.
- T1098 test 11 (exit code 1355): Unable to find a default server with Active Directory Web Services running.
- T1098 test 12 (exit code 1355): Unable to find a default server with Active Directory Web Services running.
- T1098 test 13 (exit code 1355): Unable to find a default server with Active Directory Web Services running.
- T1098 test 14 (exit code 1355): Unable to find a default server with Active Directory Web Services running.
- T1098 test 15 (exit code 1355): Unable to find a default server with Active Directory Web Services running.
- T1098 test 16 (exit code 1355): Unable to find a default server with Active Directory Web Services running.
- T1505.004 test 1 (exit code 1): operable program or batch file.
- T1505.004 test 2: New-WebGlobalModule : The term 'New-WebGlobalModule' is not recognized as the name of a cmdlet, function, script file,
- T1546 test 4: + CategoryInfo          : NotSpecified: (:) [New-CimSession], CimException
- T1197 test 4 (exit code -1): Executing test: T1197-4 Bits download using desktopimgdownldr.exe (cmd)
- T1053.002 test 1 (exit code 1): The request is not supported.
- T1078.003 test 6: Exception calling "DownloadString" with "1" argument(s): "Could not find a part of the path
- T1078.003 test 7: Exception calling "DownloadString" with "1" argument(s): "Could not find a part of the path
- T1556.001 test 1: & : The term 'C:\ExternalPayloads\Mimikatz\x64\mimikatz.exe' is not recognized as the name of a cmdlet, function,

## 5b. Failed tests, still counted (alert was produced)

- T1053.005 test 3 (exit code 1): ERROR: No mapping between account names and security IDs was done.
- T1543.003 test 1 (exit code 1053): [SC] StartService FAILED 1053:
- T1137.006 test 5 (exit code -1): Process Timed out after 100 seconds, use '-TimeoutSeconds' to specify a different timeout
- T1505.002 test 1: Install-TransportAgent : The term 'Install-TransportAgent' is not recognized as the name of a cmdlet, function, script
- T1112 test 11: New-ItemProperty : Cannot find path 'HKCU:\Software\Policies\Microsoft\Windows\System' because it does not exist.
- T1112 test 42 (exit code 1): ERROR: The system was unable to find the specified registry key or value.
- T1112 test 43 (exit code 1): ERROR: Invalid syntax.
- T1112 test 56 (exit code 1): ERROR: Access is denied.
- T1546.008 test 4 (exit code 1): The operation completed successfully.
- T1546.008 test 7 (exit code 1): The process cannot access the file because it is being used by another process.
- T1546.008 test 9 (exit code 1): The process cannot access the file because it is being used by another process.
- T1136.002 test 1 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1136.002 test 2 (exit code 2): The specified domain either does not exist or could not be contacted.
- T1547.001 test 6 (exit code -1): Process Timed out after 100 seconds, use '-TimeoutSeconds' to specify a different timeout
- T1547.001 test 14: + CategoryInfo          : InvalidArgument: (:) [Get-ItemPropertyValue], PSArgumentException
- T1547.001 test 15: + CategoryInfo          : InvalidArgument: (:) [Get-ItemPropertyValue], PSArgumentException
- T1197 test 1 (exit code -2147023651): Unable to add file - 0x800704dd
- T1197 test 2: network. The specified service does not exist. (Exception from HRESULT: 0x800704DD)
- T1197 test 3 (exit code 1): Use the job identifier instead of the job name.

## Attached files

- `charts/01_overview_donut.png`
- `charts/02_technique_status_bar.png`
- `charts/03_top_rules_bar.png`
- `charts/04_technique_heatmap.png`
- `tables/technique_detail.csv`
- `tables/rule_frequency.csv`
- `tables/failed_tests.csv`
- `tables/all_failed_tests.json` (input for `main.py --exclude-failed-tests`)
- `report_without_failed_tests.md` (companion report with every failed execution removed)
- `tables/technique_detail_without_failed_tests.csv`
- `tables/tests_without_failed_tests.csv`
- `tables/failed_but_counted.csv`
## 6. Detection source

Classified from alerts in this run. When both default and custom rules alert, the test is counted as default-detected.

- Detected by default rules: **65**
- Detected with custom rules: **127**
- Not detected: **20**
- Failed: **35**

See `tables/test_detection_source.csv` for every test.

Comparison charts: `charts/05_default_rules_coverage.png`, `charts/06_default_plus_custom_coverage.png`, `charts/07_default_rules_heatmap.png`, `charts/08_default_plus_custom_heatmap.png`, `charts/09_default_rules_technique_status.png`, and `charts/10_default_plus_custom_technique_status.png`.

Heatmaps with every failed execution removed: `charts/11_default_rules_heatmap_without_failed_tests.png` and `charts/12_default_plus_custom_heatmap_without_failed_tests.png`.
