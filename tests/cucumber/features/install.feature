Feature: CLI installation and basic usage through grob proxy

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456
    And VidaiMock is healthy on port 8100

  Scenario: grob routes a simple question via Claude Code
    Given the LLM CLI "claude" is configured
    When I ask "Quelle est la capitale de la France ?"
    Then the exit code is 0
    And the output is not empty

  Scenario: grob routes with transparency headers
    When I send a chat request with model "default" and content "ping"
    Then the response status is 200
    And the response header "x-ai-provider" exists
