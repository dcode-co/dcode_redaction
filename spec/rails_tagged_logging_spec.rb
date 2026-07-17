# frozen_string_literal: true

# Second (and last) spec that loads activesupport — real TaggedLogging.
require "active_support"
require "active_support/tagged_logging"
require "logger"
require "stringio"

RSpec.describe "DcodeRedaction.wrap_formatter with a real ActiveSupport::TaggedLogging" do
  fx = ->(*p) { p.join }

  def build_logger
    io = StringIO.new
    logger = ActiveSupport::TaggedLogging.new(Logger.new(io))
    [logger, io]
  end

  it "redacts the rendered line while preserving tags" do
    logger, io = build_logger
    expect(DcodeRedaction.wrap_formatter(logger)).to equal(logger)

    logger.tagged("req-1") do
      logger.info(fx.call("leak xai-", "abc123XYZdef456GHIjkl789"))
    end

    out = io.string
    expect(out).to include("[req-1]")
    expect(out).to include("[REDACTED:api_key]")
    expect(out).not_to include("xai-")
  end

  it "does not crash when the message is not a String" do
    logger, io = build_logger
    DcodeRedaction.wrap_formatter(logger)

    expect do
      logger.info({ "api_key" => fx.call("sk-", "ABCDEFGHIJKLMNOPQRST") })
      logger.error(StandardError.new("plain error"))
    end.not_to raise_error

    expect(io.string).not_to be_empty
  end

  it "is idempotent: wrapping twice decorates call only once" do
    logger, io = build_logger
    DcodeRedaction.wrap_formatter(logger)
    DcodeRedaction.wrap_formatter(logger)

    ancestors = logger.formatter.singleton_class.ancestors
    expect(ancestors.count { |m| m == DcodeRedaction::RedactingCall }).to eq(1)

    logger.info(fx.call("xai-", "abc123XYZdef456GHIjkl789"))
    out = io.string
    expect(out.scan("[REDACTED:api_key]").length).to eq(1)
  end
end
