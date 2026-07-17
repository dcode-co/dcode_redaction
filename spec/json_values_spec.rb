# frozen_string_literal: true

RSpec.describe "DcodeRedaction.redact_json_values" do
  fx = ->(*p) { p.join }

  it "redacts string leaves recursively in nested hashes and arrays" do
    obj = {
      "user" => "alice",
      "creds" => {
        "api_key" => fx.call("xai-", "abc123XYZdef456GHIjkl789"),
        "tokens" => [fx.call("Bearer ", "abcdefghij.klmnopqrst"), "plain"]
      },
      "count" => 3
    }
    out = DcodeRedaction.redact_json_values(obj)
    expect(out["creds"]["api_key"]).to eq("[REDACTED:api_key]")
    expect(out["creds"]["tokens"][0]).to eq("Bearer [REDACTED:bearer]")
    expect(out["creds"]["tokens"][1]).to eq("plain")
    expect(out["count"]).to eq(3)
  end

  it "leaves hash keys intact even when they look sensitive" do
    out = DcodeRedaction.redact_json_values("api_key" => "short")
    expect(out.keys).to eq(["api_key"])
  end

  it "passes through non-container scalars unchanged" do
    expect(DcodeRedaction.redact_json_values(42)).to eq(42)
    expect(DcodeRedaction.redact_json_values(nil)).to be_nil
    expect(DcodeRedaction.redact_json_values(true)).to be(true)
  end
end
