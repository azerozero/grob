Feature: Spend tracking under concurrent load

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456

  Scenario: Concurrent requests produce accurate spend total
    When 10 requests are sent concurrently
    Then the spend total reflects all 10 requests
