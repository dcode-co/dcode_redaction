# frozen_string_literal: true

# Load smoke: a fresh require compiles every pattern constant, so a malformed
# regex would raise here (fail-fast) rather than at first redaction. The
# rescue in .redact cannot catch a load-time error, so loading is its own test.
RSpec.describe "loading dcode_redaction" do
  it "requires cleanly in a fresh process with all patterns compiled" do
    script = 'require "dcode_redaction"; ' \
             'raise "no VERSION" unless DcodeRedaction::VERSION.is_a?(String); ' \
             'raise "no GATE" unless DcodeRedaction::Patterns::GATE.is_a?(Regexp); ' \
             'print "ok"'
    lib = File.expand_path("../lib", __dir__)
    out = `ruby -I#{lib} -e '#{script}' 2>&1`
    expect(out).to eq("ok"), "fresh load failed: #{out}"
  end

  it "exposes the six public API methods" do
    %i[redact redact_url redact_json_values param_filters sentry_scrub wrap_formatter].each do |m|
      expect(DcodeRedaction).to respond_to(m)
    end
  end
end
