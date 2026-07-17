# frozen_string_literal: true

RSpec.describe "DcodeRedaction.redact_url" do
  it "drops userinfo and fragment, scrubs sensitive params, keeps host/path/benign" do
    out = DcodeRedaction.redact_url(
      "https://user:pw@idp.example.com/cb?code=ABC123XYZ&page=2#access_token=DEF456"
    )
    expect(out).not_to include("user")
    expect(out).not_to include("pw")
    expect(out).not_to include("ABC123XYZ")
    expect(out).not_to include("DEF456")
    expect(out).to include("idp.example.com/cb")
    expect(out).to include("page=2")
    expect(out).to include("[REDACTED:query]")
  end

  it "leaves a fully benign URL byte-for-byte unchanged" do
    url = "https://api.example.com/v1/health?region=us-east-1"
    expect(DcodeRedaction.redact_url(url)).to eq(url)
  end

  it "preserves a non-default port" do
    out = DcodeRedaction.redact_url("https://idp.example.com:8443/cb?code=ABCDEFGH")
    expect(out).to include("idp.example.com:8443/cb")
  end

  it "scrubs every occurrence of a duplicated sensitive key" do
    out = DcodeRedaction.redact_url("https://h.io/cb?code=AAAAAAAA&code=BBBBBBBB")
    expect(out).not_to include("AAAAAAAA")
    expect(out).not_to include("BBBBBBBB")
    expect(out.scan("[REDACTED:query]").length).to eq(2)
  end

  it "matches a percent-encoded sensitive key after decoding" do
    out = DcodeRedaction.redact_url("https://h.io/cb?api%5Fkey=supersecretvalue")
    expect(out).not_to include("supersecretvalue")
    expect(out).to include("[REDACTED:query]")
  end

  it "keeps a benign param whose value merely looks long" do
    url = "https://h.io/search?region=us-east-1&page=42"
    expect(DcodeRedaction.redact_url(url)).to eq(url)
  end

  describe "malformed URL (non-recursive fallback)" do
    it "still strips userinfo and scrubs sensitive query values" do
      out = DcodeRedaction.redact_url("https://user:pw@[bad host]/cb?code=ABCDEFGH&page=2")
      expect(out).to include("[REDACTED:userinfo]")
      expect(out).not_to include("ABCDEFGH")
      expect(out).to include("[REDACTED:query]")
      expect(out).to include("page=2")
    end

    it "does not raise or recurse on a deeply malformed input" do
      weird = "https://" + ("a@b:c/" * 50) + "?token=" + ("x" * 40)
      expect { DcodeRedaction.redact_url(weird) }.not_to raise_error
    end
  end
end

RSpec.describe "URL redaction inside .redact" do
  it "redacts sensitive query params found in surrounding log text" do
    out = DcodeRedaction.redact("callback https://x.ai/cb?code=ABC123XYZ&state=xyz789 failed")
    expect(out).not_to include("ABC123XYZ")
    expect(out).not_to include("xyz789")
  end

  it "excludes trailing punctuation from the URL match" do
    out = DcodeRedaction.redact(["see `https://x.ai/cb?code=ABCD12345", "`"].join)
    expect(out).to end_with("`")
  end

  it "keeps the first pattern's label when a prior pass already redacted a query value" do
    input = ["go https://h.io/cb?api_key=sk-", "ABCDEFGHIJKLMNOPQRST", "&page=2 done"].join
    out = DcodeRedaction.redact(input)
    expect(out).to include("api_key=[REDACTED:api_key]")
    expect(out).not_to include("[REDACTED:query][REDACTED:api_key]")
    expect(out).to include("page=2")
  end
end
