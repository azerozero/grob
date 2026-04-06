Feature: Decision tokens route agents transparently

  Background:
    Given a boss agent issues decision tokens

  Scenario: Training mode routes to paper backend
    When an agent holds a decision token with mode "training"
    Then requests route to the paper backend

  Scenario: Live mode routes to real backend
    When an agent holds a decision token with mode "live"
    Then requests route to the real backend

  Scenario: Agent cannot read decision token claims
    When an agent inspects its own token
    Then the decision claims are not visible

  Scenario: Mode switch is transparent to agent
    When the boss switches an agent from training to live
    Then the agent receives the same response schema

  Scenario Outline: Invalid decision tokens are rejected
    When an agent presents a decision token with mode "<mode>"
    Then the request is <outcome>

    Examples:
      | mode    | outcome |
      | live    | routed  |
      | training| routed  |
      |         | denied  |
      | unknown | denied  |
