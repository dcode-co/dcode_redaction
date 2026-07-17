# frozen_string_literal: true

# Per-pattern positive/negative pairs. Every secret-shaped fixture is assembled
# at runtime via `fixture(...)` so no contiguous credential literal exists in
# this source.
RSpec.describe "DcodeRedaction pattern coverage" do
  # [ label, positive-fixture, expected-marker, [negatives...] ]
  cases = lambda do |f|
    [
      [
        "api_key sk-/xai-",
        [f.call("key: xai-", "abc123XYZdef456GHIjkl789"), f.call("sk-", "A" * 24), f.call("sk_", "B" * 24)],
        "[REDACTED:api_key]",
        ["task-deadbeefdeadbeefdeadbeef0123", "disk-0123456789abcdefghijklmno", "risk-0123456789abcdefghijklmno", f.call("sk-", "short")]
      ],
      [
        "aws access key",
        [f.call("aws AKIA", "ABCDEFGHIJKLMNOP key"), f.call("creds ASIA", "ABCDEFGHIJKLMNOP end")],
        "[REDACTED:aws]",
        [f.call("AKIA", "SHORT"), "NOTANAWSKEYJUSTPLAINTEXT", f.call("akia", "abcdefghijklmnop")]
      ],
      [
        "github token",
        [f.call("token ghp_", "0123456789abcdefghijABCDEFGHIJ012345"), f.call("github_pat_", "11ABCDE0123456789_abcdefghijklmnop")],
        "[REDACTED:github]",
        [f.call("ghp_", "short"), f.call("ghx_", "0123456789abcdefghij"), "the github repository is public"]
      ],
      [
        "vendor token",
        [f.call("glpat-", "0123456789abcdefABCD here"), f.call("xoxb-", "2420837490-AbCdEfGhIjKl"), f.call("xapp-1-", "A0123BCDEF-0123456789")],
        "[REDACTED:vendor]",
        [f.call("glpat-", "short"), "xbox-controller-firmware"]
      ],
      [
        "google api key",
        [f.call("AIza", "SyD0123456789abcdefghijklmnopqrstuvw")],
        "[REDACTED:google]",
        [f.call("AIza", "tooShort"), "AIzawesome product name"]
      ],
      [
        "render api key",
        [f.call("RENDER_API_KEY=rnd_", "abcdefghij0123456789")],
        "[REDACTED:render_api_key]",
        [f.call("rnd_", "short"), "we render the template server-side"]
      ],
      [
        "logi pak",
        [f.call("logi_pak_", "abcd1234", "_", "a" * 32)],
        "[REDACTED:logi_pak]",
        [f.call("logi_pak_", "abcd1234", "_", "a" * 8), "logi_packages_directory"]
      ],
      [
        "logi mcp token",
        [f.call("mcp_", "a" * 32)],
        "[REDACTED:logi_mcp_token]",
        ["mcp_config_loader_v2", f.call("mcp_", "a" * 20), "mcp server started"]
      ],
      [
        "logi client secret",
        [f.call("logi_secret_", "deadbeef" * 8)],
        "[REDACTED:logi_client_secret]",
        [f.call("logi_secret_", "deadbeef" * 4), f.call("client_id: logi_", "deadbeef" * 4), "logi_secretary_role"]
      ],
      [
        "telegram bot token",
        [f.call("bot ", "1234567890", ":AA", "Ff" * 16 + "G")],
        "[REDACTED:telegram_bot_token]",
        [f.call("1234567890", ":notatelegramtoken"), "timestamp 12:34:56 recorded", "1234567890:AAshort"]
      ],
      [
        "mcpkey header colon",
        [f.call("McpKey: ", "abcdefghij0123456789")],
        "[REDACTED:mcpkey_header]",
        ["the McpKey header is required", f.call("McpKey: ", "short")]
      ],
      [
        "bearer token",
        [f.call("Authorization: Bearer ", "abcdefghij.klmnopqrst")],
        "[REDACTED:bearer]",
        ["Bearer token", "Bearerword", f.call("Bearer ", "short")]
      ],
      [
        "bare jwt",
        [f.call("deployment key eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f")],
        "[REDACTED:jwt]",
        [f.call("eyJ", "short"), f.call("eyJhbGciOiJI", ".onlytwosegments")]
      ],
      [
        "secret assignment (unquoted)",
        [f.call("api_key=", "ABCDEFGHIJ"), f.call("password: ", "hunter2hunter2"), f.call("refresh_token=", "rt_abc1234567")],
        "[REDACTED:assignment]",
        [f.call("token: ", "abc"), "password: x", "id column is indexed"]
      ]
    ]
  end

  cases.call(->(*p) { p.join }).each do |label, positives, marker, negatives|
    describe label do
      positives.each_with_index do |input, i|
        it "redacts positive ##{i} to #{marker}" do
          out = DcodeRedaction.redact(input)
          expect(out).to include(marker), "expected #{marker} in: #{out.inspect}"
        end
      end

      negatives.each_with_index do |input, i|
        it "leaves negative ##{i} unchanged" do
          expect(DcodeRedaction.redact(input)).to eq(input)
        end
      end
    end
  end

  describe "mcpkey header alternate forms" do
    it "redacts JSON hash-rocket form, keeping the McpKey prefix" do
      input = ->(*p) { p.join }.call('{"McpKey"=>"', "abcdefghij0123456789", '"}')
      out = DcodeRedaction.redact(input)
      expect(out).to include("[REDACTED:mcpkey_header]")
      expect(out).to include("McpKey")
    end

    it "does not bleed the token match across a newline into the next log line" do
      # `\s` would include the newline and swallow the next line's identifier;
      # the horizontal-whitespace separator must stop at end of line.
      input = ->(*p) { p.join }.call("McpKey:\nnext_line_identifier_1234567890")
      expect(DcodeRedaction.redact(input)).to eq(input)
    end
  end

  describe "quoted-value app password (spaces inside quotes)" do
    it "redacts a space-containing quoted secret" do
      input = ->(*p) { p.join }.call('password="', "abcd efgh ijkl mnop", '"')
      out = DcodeRedaction.redact(input)
      expect(out).to eq('password="[REDACTED:assignment]"')
    end
  end
end
