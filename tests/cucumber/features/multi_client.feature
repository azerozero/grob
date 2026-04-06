Feature: Multi-client isolation and enforcement

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456

  # T1 — Isolation inter-projets
  Scenario: Clients on different projects cannot see each other's requests
    When client A sends a request on project "llm"
    And client C sends a request on project "analytics"
    Then audit entries for client A have project "llm"
    And audit entries for client C have project "analytics"
    And no audit entry mixes clients across projects

  Scenario: Client on analytics cannot route to anthropic
    When client C sends a request targeting provider "anthropic"
    Then the response status is 403

  # T2 — Budget isolation
  Scenario: Independent budgets per client on same project
    When client A spends up to budget limit on project "llm"
    And client B spends up to budget limit on project "llm"
    Then both clients received 200 before their limits
    And the next request from client A returns 429
    And the next request from client B returns 429

  Scenario: Unlimited budget client is not affected
    When client A has exhausted their budget
    And client C sends a request on project "analytics"
    Then client C receives 200

  # T3 — DLP cross-projet
  Scenario: GDPR DLP redacts sensitive data
    When client A sends a message containing a French SSN
    Then the response to client A does not contain the original SSN

  Scenario: Minimal DLP passes sensitive data through
    When client C sends a message containing a French SSN
    Then the response to client C contains the original SSN

  # T4 — Failover multi-LLM
  Scenario: Anthropic clients fail over when provider is down
    Given toxiproxy disables proxy "anthropic-mock"
    When client A sends a request on project "llm"
    Then client A receives 502 or falls back to secondary

  Scenario: Ollama client is not affected by anthropic outage
    Given toxiproxy disables proxy "anthropic-mock"
    When client C sends a request on project "analytics"
    Then client C receives 200
