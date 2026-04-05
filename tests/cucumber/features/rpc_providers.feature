Feature: RPC provider namespace returns live provider state

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456

  Scenario: Provider list returns configured providers
    When I call RPC "grob/provider/list"
    Then the result contains at least one provider

  Scenario: Provider score reflects health
    Given all providers are healthy
    When I call RPC "grob/provider/score"
    Then all providers have a positive score
