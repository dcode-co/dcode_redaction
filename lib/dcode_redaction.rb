# frozen_string_literal: true

require "uri"

require_relative "dcode_redaction/version"
require_relative "dcode_redaction/patterns"
require_relative "dcode_redaction/rails"

# Pure-stdlib secret redaction (no runtime dependencies).
#
# Public API:
#   DcodeRedaction.redact(text)            -> String
#   DcodeRedaction.redact_url(url_string)  -> String
#   DcodeRedaction.redact_json_values(obj) -> obj
#   DcodeRedaction.param_filters           -> [proc]   (see rails.rb)
#   DcodeRedaction.sentry_scrub(event)     -> event|nil (see rails.rb)
#   DcodeRedaction.wrap_formatter(logger)  -> logger    (see rails.rb)
module DcodeRedaction
  REDACTION_ERROR = "[REDACTION_ERROR]"

  module_function

  # Redact all known secret shapes from a log/message string.
  #
  # Fail-closed: on any unexpected runtime error (e.g. invalid string encoding)
  # the entire text is replaced with "[REDACTION_ERROR]" rather than returning
  # the original (which may contain a secret). Never logs internally — logging
  # would recurse back through the redactor.
  def redact(text)
    return text unless text.is_a?(String)

    begin
      return text unless Patterns::GATE.match?(text)

      apply_passes(text, Patterns::PASSES)
    rescue StandardError
      REDACTION_ERROR
    end
  end

  # Structurally redact a single URL: drop userinfo and fragment, replace the
  # values of sensitive query parameters, and preserve scheme/host/port/path
  # and benign parameters. On parse failure, fall back non-recursively.
  def redact_url(url_string)
    return url_string unless url_string.is_a?(String)

    begin
      parse_and_redact_url(url_string)
    rescue URI::Error, ArgumentError
      redact_url_fallback(url_string)
    end
  rescue StandardError
    # Total failure: redact the whole URL rather than leak it.
    "[REDACTED:url]"
  end

  # Recursively redact the String leaves of a JSON-like structure, returning a
  # new structure (Hash/Array copies, String leaves redacted). Keys are left
  # intact.
  def redact_json_values(obj)
    case obj
    when String then redact(obj)
    when Array  then obj.map { |v| redact_json_values(v) }
    when Hash   then obj.each_with_object({}) { |(k, v), h| h[k] = redact_json_values(v) }
    else obj
    end
  end

  # --- internal ---------------------------------------------------------

  # Apply the given ordered passes. Used by both redact (all passes) and the
  # URL fallback (all passes except :url, avoiding re-entry into redact_url).
  def apply_passes(text, passes)
    passes.reduce(text) { |acc, pass| apply_pass(acc, pass) }
  end

  def apply_pass(text, pass)
    case pass[:kind]
    when :simple
      marker = "[REDACTED:#{pass[:name]}]"
      text.gsub(pass[:regex]) { marker }
    when :simple_capture
      marker = "[REDACTED:#{pass[:name]}]"
      text.gsub(pass[:regex]) { "#{Regexp.last_match(1)}#{marker}" }
    when :bearer
      text.gsub(pass[:regex]) { "Bearer [REDACTED:bearer]" }
    when :url
      redact_urls_in(text)
    when :assignment
      text.gsub(pass[:regex]) do
        key   = Regexp.last_match(1)
        delim = Regexp.last_match(2)
        quote = Regexp.last_match(3)
        if quote
          "#{key}#{delim}#{quote}[REDACTED:assignment]#{quote}"
        else
          "#{key}#{delim}[REDACTED:assignment]"
        end
      end
    end
  end

  # Everything except the :url pass. Used by the malformed-URL fallback so it
  # cannot recurse back into redact_url.
  def redact_without_url(text)
    apply_passes(text, Patterns::PASSES.reject { |p| p[:kind] == :url })
  end

  def redact_urls_in(text)
    text.gsub(Patterns::URL) { |raw| redact_url(raw) }
  end

  # Rebuild scheme://host[:port][/path][?query] from the parsed URI, dropping
  # userinfo and fragment. Building the string manually (rather than via URI
  # setters) avoids URI component validation rejecting the "[REDACTED:query]"
  # marker.
  def parse_and_redact_url(url_string)
    uri = URI.parse(url_string)
    return redact_url_fallback(url_string) unless uri.respond_to?(:host) && uri.host

    result = +"#{uri.scheme}://#{uri.host}"
    if uri.port && uri.default_port && uri.port != uri.default_port
      result << ":#{uri.port}"
    end
    result << uri.path if uri.path && !uri.path.empty?

    query = uri.query
    if query
      scrubbed = scrub_query_string(query)
      result << "?#{scrubbed}" unless scrubbed.empty?
    end
    result
  end

  # Replace the values of sensitive parameters in a raw query string, leaving
  # keys and benign values byte-for-byte intact. Marker-guarded so an already-
  # redacted value keeps its original label.
  def scrub_query_string(query)
    query.split("&").map do |pair|
      next pair if pair.empty?

      key, sep, value = pair.partition("=")
      next pair if sep.empty?
      next pair if value.empty?
      # Guard: a prior pass may have redacted this value in place. It also
      # covers the case where URL_REGEX truncated the URL at that marker's `[`,
      # leaving an empty value here that must not be re-scrubbed into a double
      # marker.
      next pair if value.start_with?("[REDACTED:")

      decoded = begin
        URI.decode_www_form_component(key).downcase
      rescue StandardError
        key.downcase
      end
      if Patterns::SENSITIVE_QUERY_PARAMS.include?(decoded)
        "#{key}=[REDACTED:query]"
      else
        pair
      end
    end.join("&")
  end

  # Non-recursive fallback for URLs URI.parse cannot handle. Runs the non-URL
  # secret passes, then strips userinfo and scrubs sensitive query values via
  # regex. Not fail-open (userinfo + sensitive keys covered) and does not drop
  # the surrounding log line.
  def redact_url_fallback(url_string)
    s = redact_without_url(url_string)
    s = s.gsub(Patterns::USERINFO) { "://[REDACTED:userinfo]@" }
    s.gsub(Patterns::QUERY_PARAM_SCRUB) do
      "#{Regexp.last_match(1)}#{Regexp.last_match(2)}=[REDACTED:query]"
    end
  end

  # Internal helpers — kept off the public surface (only the six documented
  # methods above are API).
  private_class_method :apply_passes, :apply_pass, :redact_without_url,
                       :redact_urls_in, :parse_and_redact_url,
                       :scrub_query_string, :redact_url_fallback
end
