# frozen_string_literal: true

# The only place (besides the TaggedLogging spec) that loads activesupport.
# activesupport is a test-only Gemfile dependency, never a gem dependency.
require "active_support"
require "active_support/parameter_filter"

RSpec.describe "DcodeRedaction.param_filters with a real ActiveSupport::ParameterFilter" do
  fx = ->(*p) { p.join }
  let(:filter) { ActiveSupport::ParameterFilter.new(DcodeRedaction.param_filters) }

  # param_filters is content-based: it redacts secret-SHAPED string values
  # regardless of key (defense-in-depth beside the app's key-based filters).
  it "redacts secret-shaped string leaves in nested hashes and arrays in place" do
    input = {
      "user" => "alice",
      "api_key" => fx.call("xai-", "abc123XYZdef456GHIjkl789"),
      "nested" => {
        "creds" => fx.call("sk-", "ABCDEFGHIJKLMNOPQRST"),
        "list" => [fx.call("ghp_", "0123456789abcdefghijABCDEF"), "plain"]
      }
    }
    out = filter.filter(input)

    expect(out["user"]).to eq("alice")
    expect(out["api_key"]).to eq("[REDACTED:api_key]")
    expect(out["nested"]["creds"]).to eq("[REDACTED:api_key]")
    expect(out["nested"]["list"][0]).to eq("[REDACTED:github]")
    expect(out["nested"]["list"][1]).to eq("plain")
  end

  it "handles a frozen string value without raising (ParameterFilter dups it)" do
    frozen_secret = fx.call("xai-", "abc123XYZdef456GHIjkl789").freeze
    input = { "api_key" => frozen_secret }
    out = nil
    expect { out = filter.filter(input) }.not_to raise_error
    expect(out["api_key"]).to eq("[REDACTED:api_key]")
    # Original frozen value must be untouched (ParameterFilter mutated a dup).
    expect(frozen_secret).to eq(fx.call("xai-", "abc123XYZdef456GHIjkl789"))
  end

  it "leaves a params hash with no secret-shaped values unchanged in content" do
    input = { "page" => "2", "q" => "hello world" }
    expect(filter.filter(input)).to eq("page" => "2", "q" => "hello world")
  end
end
