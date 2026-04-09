Feature: DLP detects secrets split across SSE chunks

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456

  Scenario: Secret split between two chunks is caught
    When the provider streams a secret split across two chunks
    Then the streamed output never contains the full secret

  Scenario: Credit card split between chunks is caught
    When the provider streams a credit card split across two chunks
    Then the streamed output never contains the full number
