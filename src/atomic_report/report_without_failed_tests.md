# Detection coverage report — successful executions only

This companion report removes every failed execution before calculating statistics, rendering charts, or exporting tables. A test is removed when its result status is `failed` or its Atomic log block records an execution failure, even if that test also produced an alert.

## Overview

- Total tests recorded: **247**
- Failed executions removed: **51**
- Tests remaining: **196**
- Detected: **187** (95.4%)
- Undetected (including tests with no rule): **9**
- Techniques with at least one non-failed test: **41**

## Technique classification

- Fully detected: **34** technique(s)
- Partially detected: **4** technique(s)
- Not detected: **2** technique(s)
- No rule: **1** technique(s)

## Technique detail

| Technique   |   Tests detected |   Tests total |   Detection rate (%) | Status             | Has rule   |
|:------------|-----------------:|--------------:|---------------------:|:-------------------|:-----------|
| T1037.001   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1053.005   |               10 |            10 |                100   | Fully detected     | Yes        |
| T1078.001   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1078.003   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1098       |                1 |             1 |                100   | Fully detected     | Yes        |
| T1112       |               85 |            87 |                 97.7 | Partially detected | Yes        |
| T1133       |                0 |             1 |                  0   | Not detected       | Yes        |
| T1136.001   |                4 |             4 |                100   | Fully detected     | Yes        |
| T1137       |                1 |             1 |                100   | Fully detected     | Yes        |
| T1137.002   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1137.004   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1137.006   |                5 |             5 |                100   | Fully detected     | Yes        |
| T1505.003   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1505.005   |                1 |             2 |                 50   | Partially detected | Yes        |
| T1542.001   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1543.003   |                4 |             4 |                100   | Fully detected     | Yes        |
| T1546       |                7 |             7 |                100   | Fully detected     | Yes        |
| T1546.001   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.002   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.003   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1546.007   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.008   |                8 |             8 |                100   | Fully detected     | Yes        |
| T1546.009   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.010   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.011   |                3 |             3 |                100   | Fully detected     | Yes        |
| T1546.012   |                3 |             3 |                100   | Fully detected     | Yes        |
| T1546.013   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.015   |                3 |             3 |                100   | Fully detected     | Yes        |
| T1546.018   |                0 |             2 |                  0   | No rule            | No         |
| T1547       |                3 |             3 |                100   | Fully detected     | Yes        |
| T1547.001   |               17 |            17 |                100   | Fully detected     | Yes        |
| T1547.002   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1547.003   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1547.004   |                4 |             5 |                 80   | Partially detected | Yes        |
| T1547.005   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1547.008   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1547.009   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1547.010   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1547.012   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1547.014   |                2 |             3 |                 66.7 | Partially detected | Yes        |
| T1556.002   |                0 |             1 |                  0   | Not detected       | Yes        |

## Attached files

- `tables/technique_detail_without_failed_tests.csv`
- `tables/tests_without_failed_tests.csv`