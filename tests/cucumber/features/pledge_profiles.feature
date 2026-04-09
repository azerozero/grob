Feature: Pledge controls which tools the LLM can see

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456

  Scenario Outline: Profile determines visible tools
    Given pledge profile is "<profile>"
    When a request includes tools bash, read_file, write_file, grep
    Then the LLM sees <visible> tools
    And bash is <bash_visible>

    Examples:
      | profile   | visible | bash_visible |
      | read_only | 2       | hidden       |
      | execute   | 4       | visible      |
      | full      | 4       | visible      |
      | none      | 0       | hidden       |
