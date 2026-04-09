Feature: Audit log integrity

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456

  Scenario: Audit entries are created after requests
    When I send 3 chat requests through grob
    And I wait 2 seconds for flush
    Then the audit file has at least 3 entries
    And all audit entries are valid JSON
    And the signing key exists

  Scenario: Audit entries have required compliance fields
    When I send 3 chat requests through grob
    And I wait 2 seconds for flush
    Then all audit entries have field "model_name"
    And all audit entries have field "input_tokens"
    And all audit entries have field "output_tokens"
    And all audit entries have field "tenant_id"
    And all audit entries have field "signature"
    And all audit entries have field "signature_algorithm"
    And all audit entries have field "classification"

  Scenario: Signing algorithm is recognized
    When I send 3 chat requests through grob
    And I wait 2 seconds for flush
    Then all signature_algorithm values are valid

  Scenario: No secrets leak into audit log
    When I send 3 chat requests through grob
    And I wait 2 seconds for flush
    Then the audit log contains no secrets

  Scenario: Hash chain is tamper-evident
    When I send 5 chat requests through grob
    And I wait 2 seconds for flush
    Then all audit entries have field "previous_hash"
    And the hash chain has no duplicates
    And all event_ids are unique
