Feature: HIT Gateway scores tool calls by risk

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456
    And HIT scoring is enabled

  Scenario Outline: Tool risk determines approval policy
    When the LLM calls tool "<tool>" with "<context>"
    Then the tool call is <decision>

    Examples:
      | tool      | context        | decision       |
      | read_file | direct request | auto-approved  |
      | bash      | direct request | requires human |
      | bash      | rm -rf         | denied         |

  Scenario: MCP source increases risk level
    When the LLM calls tool "bash" from an MCP source
    Then the tool call requires human approval
