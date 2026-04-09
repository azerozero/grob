Feature: DLP scans provider responses

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456

  Scenario: Secret in LLM response is redacted
    When the provider responds with a leaked AWS key
    Then the response does not contain the original key

  Scenario: Credit card in response is redacted
    When the provider responds with a credit card number
    Then the response does not contain the original number

  Scenario: Exfiltration URL in response is neutralized
    When the provider responds with a data exfiltration URL
    Then the URL is removed from the response

  Scenario: Clean response passes through unchanged
    When the provider responds with safe text
    Then the response matches the original text
