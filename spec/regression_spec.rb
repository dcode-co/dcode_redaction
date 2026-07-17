# frozen_string_literal: true

# Regressions for leaks found in independent review (codex, 2026-07-17).
RSpec.describe "leak regressions" do
  fx = ->(*p) { p.join }

  describe "URL: sensitive non-assignment param after an earlier marker" do
    it "does not leak a code= value when api_key= was already redacted upstream" do
      input = fx.call("ping https://h.io/cb?api_key=sk-", "ABCDEFGHIJKLMNOPQRST",
                      "&code=realsecretvalue done")
      out = DcodeRedaction.redact(input)
      expect(out).not_to include("realsecretvalue")
      expect(out).to include("api_key=[REDACTED:api_key]")
      expect(out).to include("code=[REDACTED:query]")
    end
  end

  describe "URL: uppercase scheme is not a bypass" do
    it "scrubs a sensitive param under an HTTPS:// scheme" do
      expect(DcodeRedaction.redact_url("HTTPS://h.io/cb?code=SECRETCODE123"))
        .not_to include("SECRETCODE123")
    end

    it "detects an uppercase-scheme URL inside log text" do
      out = DcodeRedaction.redact("visit HTTP://h.io/cb?state=SECRETSTATE99 now")
      expect(out).not_to include("SECRETSTATE99")
    end
  end

  describe "tokens ending in - / . (no terminal \\b under-redaction)" do
    it "redacts a Bearer token whose last char is a hyphen" do
      out = DcodeRedaction.redact(fx.call("Authorization: Bearer ", "abcdefghijklmno-"))
      expect(out).to eq("Authorization: Bearer [REDACTED:bearer]")
    end

    it "redacts a JWT whose signature segment ends in a hyphen" do
      out = DcodeRedaction.redact(fx.call("key eyJhbGciOiJI", ".eyJzdWIiOiJ4In0.abcdefg-"))
      expect(out).not_to include("eyJ")
      expect(out).to include("[REDACTED:jwt]")
    end

    it "redacts a Telegram token whose last char is a hyphen" do
      out = DcodeRedaction.redact(fx.call("bot ", "1234567890", ":AA", "a" * 32 + "-"))
      expect(out).to include("[REDACTED:telegram_bot_token]")
      expect(out).not_to match(/aaaa/)
    end
  end

  describe "quoted assignment containing the opposite quote" do
    it "redacts a single-quoted value that embeds a double quote" do
      input = %q{password='ab"cd efgh ijkl'}
      expect(DcodeRedaction.redact(input)).to eq(%q{password='[REDACTED:assignment]'})
    end

    it "redacts a double-quoted value that embeds a single quote" do
      input = %q{token: "ab'cd efgh ijkl"}
      expect(DcodeRedaction.redact(input)).to eq(%q{token: "[REDACTED:assignment]"})
    end
  end

  describe "McpKey vertical vs horizontal whitespace" do
    it "redacts with a TAB separator (horizontal)" do
      out = DcodeRedaction.redact(fx.call("McpKey\t", "abcdefghij0123456789"))
      expect(out).to include("[REDACTED:mcpkey_header]")
    end

    it "does not match across a carriage return (vertical)" do
      input = fx.call("McpKey:\r", "next_line_identifier_1234567890")
      expect(DcodeRedaction.redact(input)).to eq(input)
    end
  end

  describe "Sentry fail-closed on an unwritable frozen field" do
    it "drops the event (nil) when a getter-only field holds a frozen secret" do
      secret = fx.call("xai-", "abc123XYZdef456GHIjkl789").freeze
      event = Object.new
      event.define_singleton_method(:message) { secret }
      # no message= setter -> in-place replace on a frozen string raises -> drop
      expect(DcodeRedaction.sentry_scrub(event)).to be_nil
    end
  end
end
