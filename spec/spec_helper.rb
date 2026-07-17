# frozen_string_literal: true

require "dcode_redaction"

# Assembles fixture strings at runtime so realistic-looking fake credentials
# never appear as contiguous literals in the source (keeps secret scanners /
# GitHub push protection from flagging the test corpus, and keeps this public
# repo free of secret-shaped strings).
module FixtureHelpers
  def fixture(*parts)
    parts.join
  end
end

RSpec.configure do |config|
  config.include FixtureHelpers

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
end
