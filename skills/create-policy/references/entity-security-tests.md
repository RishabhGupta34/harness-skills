# Security Tests Policies

## Package: `securityTests`
## Root path: `input[i]` (array; items have `.name` of `"output"` or `"securityTestData"`)
## Valid actions: `onstep`

## Input Schema

The security tests input is an **array** at the root level. Two main items:

- **Index 0** (`name: "output"`): Contains `outcome.outputVariables` with summary counts (strings).
- **Index 1** (`name: "securityTestData"`): Contains `outcome.issues[]` — the array of vulnerability issues.

```
input[i].name == "output"
input[i].outcome.outputVariables.CRITICAL        # string count
input[i].outcome.outputVariables.HIGH
input[i].outcome.outputVariables.MEDIUM
input[i].outcome.outputVariables.LOW
input[i].outcome.outputVariables.INFO
input[i].outcome.outputVariables.TOTAL
input[i].outcome.outputVariables.CODE_COVERAGE   # string, e.g. "85.5"
input[i].outcome.outputVariables.EXTERNAL_POLICY_FAILURES
input[i].outcome.outputVariables.APP_CRITICAL    # app-layer severity counts
input[i].outcome.outputVariables.APP_HIGH
input[i].outcome.outputVariables.BASE_CRITICAL   # base-image severity counts
input[i].outcome.outputVariables.BASE_HIGH
input[i].outcome.outputVariables.BASE_IMAGE_APPROVED  # "true"/"false"

input[i].name == "securityTestData"
input[i].outcome.issues[j].created               # Unix timestamp in seconds (e.g. 1770127130)
input[i].outcome.issues[j].id                    # Unique issue ID string
input[i].outcome.issues[j].issueType             # "SCA", "SAST", "DAST", etc.
input[i].outcome.issues[j].key                   # Issue key (e.g. "pyyaml//3.13")
input[i].outcome.issues[j].title
input[i].outcome.issues[j].numOccurrences        # Integer count
input[i].outcome.issues[j].occurrences[k]        # array of occurrence details
input[i].outcome.issues[j].details.severityCode  # "Critical", "High", "Medium", "Low", "Info" (Title Case)
input[i].outcome.issues[j].details.severity      # Numeric CVSS score (e.g. 9.8)
input[i].outcome.issues[j].details.title         # Package identifier (e.g. "pkg:pypi/pyyaml@3.13")
input[i].outcome.issues[j].details.issueDescription  # Vulnerability description
input[i].outcome.issues[j].details.libraryName   # Affected library
input[i].outcome.issues[j].details.currentVersion    # Current version string
input[i].outcome.issues[j].details.referenceIdentifiers[l].id    # WITHOUT prefix, e.g. "2020-14343" (NOT "CVE-2020-14343")
input[i].outcome.issues[j].details.referenceIdentifiers[l].type  # "cve", "cwe", "ghsa"
input[i].outcome.issues[j].details.epss          # EPSS score (float)
input[i].outcome.issues[j].details.epssPercentile # EPSS percentile (float)
input[i].outcome.issues[j].details.reachability  # "reachable", "unreachable", "unknown"
input[i].outcome.issues[j].details.productName   # Scanner product name
```

### IMPORTANT RULES for security test policies:
1. Access issues via `input[1].outcome.issues[_]` since the input root is a plain array.
2. **Always use `issue.details.severityCode`** for severity checks, NOT `issue.severityCode`.
3. Severity values are **Title Case**: `"Critical"`, `"High"`, `"Medium"`, `"Low"` — never lowercase.
4. CVE IDs do NOT have a `"CVE-"` prefix — they are bare like `"2020-14343"`.
5. EPSS fields are flat: `issue.details.epss` and `issue.details.epssPercentile` (NOT nested under `.score`/`.percentile`).
6. Reachability is under `issue.details.reachability`, NOT `issue.reachability`.

## Example 1: Block by severity

**Scenario:** Deny if any issue matches Info or Low severity.

```rego
package securityTests

import future.keywords.in
import future.keywords.if

deny_list := fill_defaults([
  { "severity": {"value": "Info", "operator": "=="} },
  { "severity": {"value": "Low", "operator": "=="} }
])

deny[msg] {
  item = deny_list_violations[i][j]
  issue := item.issue
  violation = item.violation
  msg := sprintf("Vulnerability ['%s'] matches deny list '%s'", [issue.title, violation])
}

deny_list_violations[violations] {
    input[i].name == "securityTestData"
    issue := input[i].outcome.issues[j]
    violations := [x |
        x := {
            "issue": {"title": issue.title},
            "violation": remove_null(deny_list[k])
        }
        deny_compare(issue, deny_list[k])
        count(x.violation) > 0
    ]
    count(violations) > 0
}

deny_compare(issue, rule) := true if {
  str_compare(issue.title, rule.title.operator, rule.title.value)
  num_compare(count(issue.occurrences), rule.maxOccurrences.operator, rule.maxOccurrences.value)
  str_compare(issue.details.severityCode, rule.severity.operator, rule.severity.value)
  ri_array := default_ri(issue)
  ri := ri_array[l]
  str_compare(ri.id, rule.refId.operator, rule.refId.value)
  str_compare(ri.type, rule.refType.operator, rule.refType.value)
}

str_compare(a, "==", b) := a == b
str_compare(a, "!", b) := a != b
str_compare(a, "~", b) := regex.match(b, a)
str_compare(a, null, b) := a == b if { b != null }
str_compare(a, null, null) := true

num_compare(a, "==", b) := a == b
num_compare(a, "<=", b) := a <= b
num_compare(a, ">=", b) := a >= b
num_compare(a, "<", b) := a < b
num_compare(a, ">", b) := a > b
num_compare(a, null, b) := a == b if { b != null }
num_compare(a, null, null) := true

remove_null(obj) := filtered {
  filtered := {x | x := obj[_]; x.value != null}
}

default_ri(issue) := issue.details.referenceIdentifiers if {
    count(issue.details.referenceIdentifiers) != 0
} else := [{"id": "", "type": ""}]

fill_defaults(obj) := list {
    defaults := {
        "title": {"value": null, "operator": null},
        "maxOccurrences": {"value": null, "operator": null},
        "severity": {"value": null, "operator": null},
        "refId": {"value": null, "operator": null},
        "refType": {"value": null, "operator": null},
        "year": {"value": null, "operator": null},
    }
    list := [x | x := object.union(defaults, obj[_])]
}
```

## Example 2: Block by code coverage threshold

**Scenario:** Deny if code coverage is below 50%.

```rego
package securityTests

deny[msg] {
  input[i].name == "output"
  code_coverage := to_number(input[i].outcome.outputVariables.CODE_COVERAGE)
  code_coverage < 50.0
  msg := sprintf("Code Coverage is %.1f%%, which is below the minimum threshold of 50%%", [code_coverage])
}
```

## Example 3: Block by external policy failures

**Scenario:** Deny if any external policy failures are reported.

```rego
package securityTests

deny[msg] {
  input[i].name == "output"
  failures := to_number(input[i].outcome.outputVariables.EXTERNAL_POLICY_FAILURES)
  failures > 0
  msg := sprintf("External policy failures detected: %d", [failures])
}
```

## Example 4: Block reachable vulnerabilities

**Scenario:** Deny if more than N reachable issues exist.

```rego
package securityTests

import future.keywords.in
import future.keywords.if

maxReachableIssuesCount := 0

deny[msg] {
  input[i].name == "securityTestData"
  reachable_issues := [issue |
    some issue in input[i].outcome.issues
    issue.details.reachability == "reachable"
  ]
  count(reachable_issues) > maxReachableIssuesCount
  msg := sprintf("Found %d reachable vulnerabilities, maximum allowed is %d", [count(reachable_issues), maxReachableIssuesCount])
}
```

## Example 5: Block by EPSS score threshold

**Scenario:** Deny if any vulnerability exceeds an EPSS score or percentile threshold.

```rego
package securityTests

import future.keywords.in
import future.keywords.if

max_issues := 0
epss_threshold := 90.0
epss_percentile_threshold := 90.0

deny[msg] {
  unique_issue_ids := {issue.id |
    some i, j
    input[i].name == "securityTestData"
    issue := input[i].outcome.issues[j]
    issue.details.epss != null
    round_off(issue.details.epss) > epss_threshold
    round_off(issue.details.epssPercentile) > epss_percentile_threshold
  }
  issue_count := count(unique_issue_ids)
  issue_count > max_issues
  msg := sprintf("Found %d issue(s) exceeding EPSS thresholds (score > %.1f, percentile > %.1f)", [issue_count, epss_threshold, epss_percentile_threshold])
}

round_off(score) := result {
  result = round(score * 1000) / 10.0
}
```

## Example 6: Block app-layer vulnerabilities with base image exemption

**Scenario:** Block pipelines with app-layer or base-image vulnerabilities. Skip base image checks if `BASE_IMAGE_APPROVED` is "true".

```rego
package securityTests

import future.keywords.in
import future.keywords.if

deny_list := [
  { "name": "APP_CRITICAL", "value": 0, "operator": ">" },
  { "name": "APP_HIGH", "value": 0, "operator": ">" },
  { "name": "BASE_CRITICAL", "value": 0, "operator": ">" },
  { "name": "BASE_HIGH", "value": 0, "operator": ">" }
]

deny[msg] {
  input[i].name == "output"
  output_variables := input[i].outcome.outputVariables
  not ignore_base_vulns(output_variables)
  ov_name := object.keys(output_variables)[_]
  rule := deny_list[_]
  ov_name == rule.name
  num_compare(to_number(output_variables[ov_name]), rule.operator, rule.value)
  msg := sprintf("Pipeline blocked: Output Variable '%s' = %s violates threshold %v %v", [ov_name, output_variables[ov_name], rule.operator, rule.value])
}

ignore_base_vulns(output_variables) {
  status := output_variables["BASE_IMAGE_APPROVED"]
  lower(status) == "true"
}

num_compare(a, "==", b) := a == b
num_compare(a, "<=", b) := a <= b
num_compare(a, ">=", b) := a >= b
num_compare(a, "<", b) := a < b
num_compare(a, ">", b) := a > b
```

## Example 7: Block critical vulnerabilities older than N days

**Scenario:** Deny if any critical vulnerability has a CVE age exceeding 30 days.

```rego
package securityTests

# Maximum allowed age in days for critical vulnerabilities
max_critical_age_days = 30

# Seconds in a day
seconds_per_day = 86400

# Deny if any critical vulnerability is older than the max allowed age
deny[msg] {
  # Access issues from the securityTestData entry (index 1)
  issue = input[1].outcome.issues[_]

  # Check for Critical severity (Title Case, under details)
  issue.details.severityCode == "Critical"

  # Calculate age in days from the unix timestamp
  age_in_days = (time.now_ns() / 1000000000 - issue.created) / seconds_per_day
  age_in_days > max_critical_age_days

  msg := sprintf(
    "Critical vulnerability '%s' (CVSS: %v) is %.0f days old, exceeding the maximum allowed age of %d days",
    [issue.details.title, issue.details.severity, age_in_days, max_critical_age_days]
  )
}
```

## Key Notes

- The security tests input is an **array at root level**, not nested under a key.
- Use `input[i].name == "securityTestData"` to find issue data.
- Use `input[i].name == "output"` to find aggregate counts.
- The `deny_list` + `fill_defaults` + `deny_compare` pattern is the standard approach for configurable security policies. Customize only the `deny_list` entries.
- `outputVariables` values are **strings** — convert with `to_number()` before comparing.
