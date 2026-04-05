Feature: Setup wizard lifecycle

  The wizard collects choices, shows a recap, and writes config atomically.

  Background:
    Given a clean grob home directory

  Scenario: Unattended setup produces a working config
    When I run setup with defaults
    Then a valid config is created

  Scenario: Dry run previews without writing
    When I run setup with defaults and dry run
    Then no config is written

  Scenario: Re-running setup creates a backup
    Given a previous setup was completed
    When I run setup with defaults
    Then a backup of the previous config exists

  Scenario: API keys are never stored in cleartext
    When I run setup with defaults
    Then all credentials use environment variable references

  Scenario: Doctor passes after a clean setup
    Given a previous setup was completed
    When I run doctor
    Then the doctor reports no errors

  Scenario: Preset dry run does not modify config
    Given a previous setup was completed
    When I apply preset "fast" with dry run
    Then the config is unchanged
