Feature: Sokolsky log backend integration

  Grob serves as the access point for agents querying audit logs stored in
  sokolsky-collector. Access is controlled by role, plane, and backend,
  with DLP redaction applied on output.

  # T-SOK-1 — Plane isolation by role
  Scenario Outline: Role-based plane access
    Given an agent authenticated as "<role>"
    When the agent queries the "<plane>" plane
    Then the response status is "<status>"

    Examples:
      | role    | plane   | status  |
      | admin   | machine | allowed |
      | admin   | app     | allowed |
      | admin   | audit   | allowed |
      | devops  | machine | allowed |
      | devops  | app     | allowed |
      | devops  | audit   | denied  |
      | dev     | app     | allowed |
      | dev     | machine | denied  |
      | dev     | audit   | denied  |
      | auditor | machine | allowed |
      | auditor | app     | allowed |
      | auditor | audit   | allowed |

  # T-SOK-2 — N-of-N signature verification
  Scenario: Valid N-of-N signatures pass verification
    Given a log entry signed by all three planes
    When the signatures are verified
    Then verification succeeds

  Scenario: Missing plane signature fails verification
    Given a log entry missing the audit plane signature
    When the signatures are verified
    Then verification fails with an integrity violation

  # T-SOK-3 — DLP redaction on sokolsky log fields
  Scenario: Devops role gets PII fields redacted
    Given a decrypted log containing PII fields
    When a devops agent reads the log
    Then the PII fields are redacted in the response

  # T-SOK-4 — Multi-backend aggregation
  Scenario: Admin aggregates logs across backends
    Given logs with the same trace across multiple backends
    When an admin queries with aggregation
    Then the response contains entries from all backends sorted by timestamp
