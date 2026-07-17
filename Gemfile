# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# activesupport is used ONLY by the ParameterFilter and TaggedLogging
# integration specs; it is not a gem dependency (runtime or gemspec-declared).
group :test do
  gem "activesupport"
end
