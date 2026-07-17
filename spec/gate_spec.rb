# frozen_string_literal: true

RSpec.describe "DcodeRedaction gate and tripwire" do
  fx = ->(*p) { p.join }

  # Every full-pattern-positive fixture. If any of these matches its full
  # pattern but NOT the gate, redaction would be silently skipped.
  positives = [
    fx.call("xai-", "abc123XYZdef456GHIjkl789"),
    fx.call("sk-", "A" * 24),
    fx.call("AKIA", "ABCDEFGHIJKLMNOP"),
    fx.call("ASIA", "ABCDEFGHIJKLMNOP"),
    fx.call("ghp_", "0123456789abcdefghijABCDEF"),
    fx.call("github_pat_", "11ABCDE0123456789_abcdefghij"),
    fx.call("glpat-", "0123456789abcdefABCD"),
    fx.call("xoxb-", "2420837490-AbCdEfGhIjKl"),
    fx.call("xapp-1-", "A0123BCDEF-0123456789"),
    fx.call("AIza", "SyD0123456789abcdefghijklmnopqrstuvw"),
    fx.call("-----BEGIN ", "PRIVATE KEY-----\n", "MIIabc\n", "-----END ", "PRIVATE KEY-----"),
    fx.call("Bearer ", "abcdefghij.klmnopqrst"),
    fx.call("eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiJ4In0.SflKxwRJSMeKKF2Q"),
    fx.call("rnd_", "abcdefghij0123456789"),
    fx.call("logi_pak_", "abcd1234", "_", "a" * 32),
    fx.call("mcp_", "a" * 32),
    fx.call("logi_secret_", "deadbeef" * 8),
    fx.call("1234567890", ":AA", "Ff" * 16 + "G"),
    fx.call("McpKey: ", "abcdefghij0123456789"),
    fx.call("api_key=", "ABCDEFGHIJ"),
    fx.call("password=\"", "abcd efgh ijkl mnop", "\""),
    "https://x.ai/cb?code=ABC123XYZ"
  ]

  describe "implication: full-pattern match => gate match" do
    positives.each_with_index do |input, i|
      it "gate matches positive fixture ##{i}" do
        full_hit = DcodeRedaction::Patterns::PASSES.any? do |pass|
          pass[:regex].match?(input)
        end
        expect(full_hit).to be(true), "no full pattern matched fixture ##{i}: #{input.inspect}"
        expect(DcodeRedaction::Patterns::GATE.match?(input)).to be(true),
               "gate missed a full-pattern positive ##{i}: #{input.inspect}"
      end
    end
  end

  describe "tripwire: pattern count consistency" do
    it "has 16 passes, 16 gate anchors, and 16 distinct names" do
      passes = DcodeRedaction::Patterns::PASSES
      anchors = DcodeRedaction::Patterns::GATE_ANCHORS
      expect(passes.length).to eq(16)
      expect(anchors.length).to eq(16)
      expect(passes.map { |p| p[:name] }.uniq.length).to eq(16)
      expect(DcodeRedaction::Patterns::PATTERN_COUNT).to eq(16)
    end

    it "declares 17 sensitive URL query params (grok 16 + mcp_key)" do
      params = DcodeRedaction::Patterns::SENSITIVE_QUERY_PARAMS
      expect(params.length).to eq(17)
      expect(params).to include("mcp_key")
    end
  end
end
