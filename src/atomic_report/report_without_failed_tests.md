# Detection coverage report — successful executions only

This companion report removes every failed execution before calculating statistics, rendering charts, or exporting tables. A test is removed when its result status is `failed` or its Atomic log block records an execution failure, even if that test also produced an alert.

## Overview

- Total tests recorded: **247**
- Failed executions removed: **54**
- Tests remaining: **193**
- Detected: **173** (89.6%)
- Undetected (including tests with no rule): **20**
- Techniques with at least one non-failed test: **40**

## Technique classification

- Fully detected: **33** technique(s)
- Partially detected: **4** technique(s)
- Not detected: **1** technique(s)
- No rule: **2** technique(s)

## Technique detail

| Technique   |   Tests detected |   Tests total |   Detection rate (%) | Status             | Has rule   |
|:------------|-----------------:|--------------:|---------------------:|:-------------------|:-----------|
| T1037.001   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1053.005   |               10 |            10 |                100   | Fully detected     | Yes        |
| T1078.001   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1078.003   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1098       |                1 |             1 |                100   | Fully detected     | Yes        |
| T1112       |               74 |            86 |                 86   | Partially detected | Yes        |
| T1133       |                0 |             1 |                  0   | Not detected       | Yes        |
| T1136.001   |                4 |             4 |                100   | Fully detected     | Yes        |
| T1137       |                1 |             1 |                100   | Fully detected     | Yes        |
| T1137.002   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1137.004   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1137.006   |                4 |             4 |                100   | Fully detected     | Yes        |
| T1505.003   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1505.005   |                0 |             2 |                  0   | No rule            | No         |
| T1542.001   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1543.003   |                3 |             4 |                 75   | Partially detected | Yes        |
| T1546       |                8 |             8 |                100   | Fully detected     | Yes        |
| T1546.001   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.002   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.003   |                2 |             2 |                100   | Fully detected     | Yes        |
| T1546.007   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.008   |                6 |             6 |                100   | Fully detected     | Yes        |
| T1546.009   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.010   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.011   |                3 |             3 |                100   | Fully detected     | Yes        |
| T1546.012   |                3 |             3 |                100   | Fully detected     | Yes        |
| T1546.013   |                1 |             1 |                100   | Fully detected     | Yes        |
| T1546.015   |                4 |             4 |                100   | Fully detected     | Yes        |
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

## Attached files

- `tables/technique_detail_without_failed_tests.csv`
- `tables/tests_without_failed_tests.csv`