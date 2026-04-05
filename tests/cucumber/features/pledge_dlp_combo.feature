Feature: Pledge and DLP work together as defense in depth

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456
    And pledge profile is "read_only"

  Scenario: Injection in response is redacted AND bash is structurally absent
    When the provider responds with a prompt injection targeting bash
    Then the injection is redacted in the response
    And the LLM tool list does not contain bash

  Scenario: Secret is redacted AND tools are filtered in same request
    When I send a request containing a secret and tools bash, read_file
    Then the secret is redacted in the forwarded prompt
    And the LLM only sees read_file
