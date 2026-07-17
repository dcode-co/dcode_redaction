# frozen_string_literal: true

RSpec.describe "DcodeRedaction.redact" do
  fx = ->(*p) { p.join }

  describe "gate short-circuit" do
    it "returns the exact same object for a line with no secret shapes" do
      input = "just a normal log line"
      expect(DcodeRedaction.redact(input)).to equal(input)
    end

    it "leaves model/version-looking strings alone" do
      expect(DcodeRedaction.redact("model=grok-3")).to eq("model=grok-3")
    end
  end

  describe "negative corpus (no over-redaction)" do
    corpus = [
      "config/database.yml loaded",
      "app/models/user.rb:42 in `save'",
      "trace_id=00f067aa0ba902b7 span_id=00f067aa0ba902b7",
      "uuid 550e8400-e29b-41d4-a716-446655440000 created",
      "The quick brown fox jumps over the lazy dog.",
      "code review scheduled for 3pm",
      "https://api.example.com/v1/health?region=us-east-1",
      "GET /users/1234/profile 200 OK",
      "disk-0123456789abcdefghijklmno mounted",
      "risk-assessment-report-final"
    ]
    corpus.each do |line|
      it "leaves #{line.inspect} unchanged" do
        expect(DcodeRedaction.redact(line)).to eq(line)
      end
    end
  end

  describe "marker protection (typed labels survive later passes)" do
    it "keeps the api_key label for an unquoted assignment value" do
      out = DcodeRedaction.redact(fx.call("password=sk-", "ABCDEFGHIJKLMNOPQRST"))
      expect(out).to eq("password=[REDACTED:api_key]")
    end

    it "keeps the api_key label inside a quoted assignment value" do
      out = DcodeRedaction.redact(fx.call('token: "sk-', "ABCDEFGHIJKLMNOPQRST", '"'))
      expect(out).to eq('token: "[REDACTED:api_key]"')
    end

    it "keeps the jwt label for a token= assignment" do
      out = DcodeRedaction.redact(fx.call("token=eyJab", "cdefgh.ijklmnop.qrstuvwx"))
      expect(out).to eq("token=[REDACTED:jwt]")
    end
  end

  describe "multiline PEM (m flag)" do
    it "redacts the whole block including the base64 body across newlines" do
      pem = fx.call(
        "-----BEGIN ", "PRIVATE KEY-----\n",
        "MIIabc123def456\nMIIxyz789\n",
        "-----END ", "PRIVATE KEY-----"
      )
      out = DcodeRedaction.redact("key:\n#{pem}\ndone")
      expect(out).to eq("key:\n[REDACTED:pem]\ndone")
      expect(out).not_to include("MIIabc123")
      expect(out).not_to include("BEGIN PRIVATE KEY")
    end

    it "redacts an EC PRIVATE KEY block (typed header)" do
      pem = fx.call(
        "-----BEGIN ", "EC PRIVATE KEY-----\n",
        "MHcCAQEEIabc\nMHcCAQEEIxyz\n",
        "-----END ", "EC PRIVATE KEY-----"
      )
      expect(DcodeRedaction.redact(pem)).to eq("[REDACTED:pem]")
    end
  end

  describe "fail-closed runtime boundary" do
    it "returns [REDACTION_ERROR] for a string with invalid encoding" do
      bad = (+"model=grok").force_encoding("UTF-8") + 255.chr.force_encoding("UTF-8")
      expect(bad.valid_encoding?).to be(false)
      expect(DcodeRedaction.redact(bad)).to eq("[REDACTION_ERROR]")
    end

    it "returns [REDACTION_ERROR] (never the original) if a pass raises" do
      input = fx.call("key xai-", "abc123XYZdef456GHIjkl789")
      allow(DcodeRedaction).to receive(:apply_passes).and_raise(RuntimeError, "boom")
      out = DcodeRedaction.redact(input)
      expect(out).to eq("[REDACTION_ERROR]")
      expect(out).not_to include("xai-")
    end

    it "never emits an internal log while failing closed" do
      # No logger is wired in; assert the error path does not attempt to print.
      bad = (+"x").force_encoding("UTF-8") + 254.chr.force_encoding("UTF-8")
      expect { DcodeRedaction.redact(bad) }.not_to output.to_stderr
    end
  end

  describe "non-string input" do
    it "returns the argument unchanged for nil" do
      expect(DcodeRedaction.redact(nil)).to be_nil
    end
  end
end
