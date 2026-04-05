Feature: Provider failover via Toxiproxy

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456
    And Toxiproxy API is available on port 8474

  Scenario: Fallback to secondary when primary is down
    Given toxiproxy disables proxy "anthropic-mock"
    When I send a chat request with model "default" and content "ping"
    Then the response status is 200
    And the response header "x-ai-provider" does not contain "anthropic"

  Scenario: 502 when all providers are down
    Given toxiproxy disables proxy "anthropic-mock"
    And toxiproxy disables proxy "openai-mock"
    And toxiproxy disables proxy "gemini-mock"
    When I send a chat request with model "default" and content "ping"
    Then the response status is 502
