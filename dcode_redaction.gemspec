# frozen_string_literal: true

require_relative "lib/dcode_redaction/version"

Gem::Specification.new do |spec|
  spec.name        = "dcode_redaction"
  spec.version     = DcodeRedaction::VERSION
  spec.authors     = ["Dcode"]
  spec.email       = ["support@1pass.dev"]

  spec.summary     = "Pure-stdlib secret redaction for logs, params, Sentry events, and URLs."
  spec.description = "Value-pattern secret redactor with zero runtime dependencies. " \
                     "Redacts API keys, tokens, PEM blocks, JWTs, and sensitive URL " \
                     "parameters from strings, with duck-typed adapters for Rails " \
                     "parameter filtering, Sentry event scrubbing, and log formatters."
  spec.homepage    = "https://github.com/dcode-co/dcode_redaction"
  spec.license     = "MIT"

  spec.required_ruby_version = ">= 3.1"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir[
    "lib/**/*.rb",
    "README.md",
    "LICENSE.txt"
  ]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rspec", "~> 3.0"
end
