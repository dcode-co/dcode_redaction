# frozen_string_literal: true

require "logger"

module DcodeRedaction
  # Prepended onto a log formatter's singleton class so only `call` is
  # decorated; the original formatter object (and its tag state, for
  # ActiveSupport::TaggedLogging) is preserved.
  module RedactingCall
    def call(severity, time, progname, msg)
      DcodeRedaction.redact(super)
    end
  end

  module_function

  # Filters for `config.filter_parameters`. ActiveSupport::ParameterFilter
  # invokes a proc filter as `(key, value)` and IGNORES the return value, so
  # the value must be mutated in place. ParameterFilter passes a dup of the
  # value, so mutating a frozen original is safe.
  def param_filters
    [
      lambda do |_key, value|
        value.replace(redact(value)) if value.is_a?(String)
      end
    ]
  end

  # Duck-typed, in-place scrub of the String leaves of a Sentry event
  # (error or transaction). Returns the SAME event object (never a Hash).
  # On any internal error returns nil, dropping the event (fail-closed —
  # a possibly-secret-bearing event is not emitted).
  def sentry_scrub(event)
    return event if event.nil?

    scrub_event_message(event)
    scrub_event_exception(event)
    scrub_event_breadcrumbs(event)
    scrub_event_request(event)
    scrub_attr(event, :extra)
    scrub_attr(event, :tags)
    scrub_attr(event, :contexts)
    scrub_attr(event, :user)
    scrub_event_spans(event)

    event
  rescue StandardError, SystemStackError
    # Fail-closed on ANY internal error, including a stack overflow from a
    # pathological (e.g. cyclic) structure — drop the event rather than emit a
    # possibly-secret-bearing one. SystemStackError is not a StandardError, so
    # it must be named explicitly.
    nil
  end

  # Decorate `logger.formatter#call` to redact rendered output, preserving the
  # formatter object so TaggedLogging's tag delegation keeps working. Idempotent.
  def wrap_formatter(logger)
    formatter = logger.formatter
    formatter ||= (logger.formatter = ::Logger::Formatter.new)

    singleton = formatter.singleton_class
    singleton.prepend(RedactingCall) unless singleton.include?(RedactingCall)
    logger
  end

  # --- internal sentry helpers -----------------------------------------

  def scrub_event_message(event)
    scrub_attr(event, :message)
  end

  def scrub_event_exception(event)
    return unless event.respond_to?(:exception)

    exception = event.exception
    return if exception.nil?
    return deep_redact!(exception) if exception.is_a?(Hash)
    return unless exception.respond_to?(:values)

    values = exception.values
    return unless values.is_a?(Array)

    values.each do |single|
      next if single.nil?

      if single.is_a?(Hash)
        deep_redact!(single)
      else
        scrub_attr(single, :value)
        scrub_stacktrace_vars(single)
      end
    end
  end

  # Stack-frame local variables (`frame.vars`) are a Sentry PII sink when
  # captured. Duck-typed and no-op when frames/vars are absent (the default
  # under send_default_pii=false).
  def scrub_stacktrace_vars(single)
    return unless single.respond_to?(:stacktrace)

    stacktrace = single.stacktrace
    return if stacktrace.nil?
    return deep_redact!(stacktrace) if stacktrace.is_a?(Hash)
    return unless stacktrace.respond_to?(:frames)

    frames = stacktrace.frames
    return unless frames.is_a?(Array)

    frames.each { |frame| scrub_element(frame, :vars) }
  end

  def scrub_event_breadcrumbs(event)
    return unless event.respond_to?(:breadcrumbs)

    breadcrumbs = event.breadcrumbs
    return if breadcrumbs.nil?
    # Serialized breadcrumbs can arrive as a Hash (e.g. {"values" => [...]});
    # deep-redact the whole structure in that case.
    return deep_redact!(breadcrumbs) if breadcrumbs.is_a?(Hash)

    buffer = breadcrumbs.respond_to?(:buffer) ? breadcrumbs.buffer : breadcrumbs
    return unless buffer.is_a?(Array)

    buffer.each { |crumb| scrub_element(crumb, :message, :data) }
  end

  def scrub_event_request(event)
    return unless event.respond_to?(:request)

    request = event.request
    return if request.nil?
    return deep_redact!(request) if request.is_a?(Hash)

    scrub_attr(request, :url)
    scrub_attr(request, :query_string)
    scrub_attr(request, :data)
    scrub_attr(request, :headers)
    scrub_attr(request, :cookies)
    scrub_attr(request, :env)
  end

  def scrub_event_spans(event)
    return unless event.respond_to?(:spans)

    spans = event.spans
    return unless spans.is_a?(Array)

    spans.each { |span| scrub_element(span, :description, :data, :tags) }
  end

  # Scrub a field element that may be EITHER a Hash (String/Symbol keys — e.g.
  # logi's TransactionEvent#spans, already `to_hash`'d at event-build time) OR
  # an attribute-style interface object. A Hash is deep-redacted whole (covers
  # every String leaf regardless of key type); an object gets its named
  # String/Hash attributes redacted.
  def scrub_element(element, *string_attrs)
    return if element.nil?

    if element.is_a?(Hash)
      deep_redact!(element)
    else
      string_attrs.each { |attr| scrub_attr(element, attr) }
    end
  end

  # Read `obj.attr`; if it is a String, redact and write back (via setter if
  # present, else in-place replace); if a Hash/Array, deep-redact in place.
  def scrub_attr(obj, attr)
    return unless obj.respond_to?(attr)

    value = obj.public_send(attr)
    case value
    when String
      redacted = redact(value)
      return if redacted.equal?(value) || redacted == value

      setter = "#{attr}="
      if obj.respond_to?(setter)
        obj.public_send(setter, redacted)
      else
        # No setter: mutate the String the event holds. If it is frozen this
        # raises FrozenError and propagates to sentry_scrub, which drops the
        # event (fail-closed) rather than emitting the unredacted secret.
        value.replace(redacted)
      end
    when Hash, Array
      deep_redact!(value)
    end
  end

  # In-place deep redaction of String leaves within nested Hash/Array
  # containers. Containers are mutated and returned; a String argument returns
  # a new redacted String (caller assigns).
  def deep_redact!(obj)
    case obj
    when String
      redact(obj)
    when Hash
      obj.each { |k, v| obj[k] = deep_redact!(v) }
      obj
    when Array
      obj.map! { |v| deep_redact!(v) }
      obj
    else
      obj
    end
  end

  # Internal Sentry helpers — kept off the public surface.
  private_class_method :scrub_event_message, :scrub_event_exception,
                       :scrub_stacktrace_vars, :scrub_event_breadcrumbs,
                       :scrub_event_request, :scrub_event_spans,
                       :scrub_element, :scrub_attr, :deep_redact!
end
