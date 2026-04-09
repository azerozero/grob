Feature: Full round-trip request tracing

  Background:
    Given the e2e pod is running
    And grob is healthy on port 13456
    And full tracing is enabled

  Scenario: All 6 stages are logged for a normal request
    When I send a request containing a secret
    Then the trace file contains stage "req_in" with the original request
    And the trace file contains stage "dlp_req" with the transformation
    And the trace file contains stage "req_out" with the sanitized request
    And the trace file contains stage "res_in" with the provider response
    And the trace file contains stage "res_out" with the client response

  Scenario: DLP transformation shows before and after
    When I send a request containing a secret
    Then the "dlp_req" stage shows the original value
    And the "dlp_req" stage shows the replacement value
    And the "dlp_req" stage shows which rule triggered

  Scenario: Streaming response stages are logged per chunk
    When I send a streaming request
    Then the trace contains "res_in" entries for each chunk
    And the trace contains "res_out" entries for the sanitized chunks
