# dcode_redaction

Pure-stdlib secret redaction for Ruby logs, parameters, Sentry events, and URLs.
**Zero runtime dependencies** (only `uri` from the standard library). Rails and
Sentry integration is provided through duck-typed adapters, so the gem never
depends on Rails or the sentry gem.

It redacts by **value shape** — API keys, tokens, PEM private-key blocks, JWTs,
and sensitive URL parameters — and is designed to sit *beside* your existing
key-based filtering (Rails `filter_parameters`, a Sentry scrubber) as
defense-in-depth, not as a replacement.

## What it catches

16 value patterns (10 general + 6 Dcode-specific): `sk-`/`sk_`/`xai-` API keys,
AWS access keys, GitHub PATs, GitLab/Slack tokens, Google API keys, PEM private
keys, `Bearer` tokens, bare JWTs, secret assignments (`key = value`), Render API
keys, logi PAKs, logi MCP tokens, logi client secrets, Telegram bot tokens, and
`McpKey` headers. In URLs it scrubs the values of 17 sensitive query parameters
(`access_token`, `api_key`, `code`, `token`, `mcp_key`, …) and strips userinfo
and fragments.

Replacements are labeled: `[REDACTED:<pattern>]`, e.g. `[REDACTED:api_key]`,
`[REDACTED:jwt]`, `[REDACTED:query]`.

## Install

Pin to a **tag** (never a branch — a moving branch changes redaction behavior
under you):

```ruby
# Gemfile
gem "dcode_redaction", git: "https://github.com/dcode-co/dcode_redaction.git", tag: "v0.1.0"
```

## Public API

```ruby
DcodeRedaction.redact(text)            # -> String, redacts all secret shapes
DcodeRedaction.redact_url(url_string)  # -> String, structural URL redaction
DcodeRedaction.redact_json_values(obj) # -> obj, redacts String leaves of Hash/Array
DcodeRedaction.param_filters           # -> [proc] for config.filter_parameters
DcodeRedaction.sentry_scrub(event)     # -> event | nil (fail-closed drop)
DcodeRedaction.wrap_formatter(logger)  # -> logger, decorates the formatter
```

## Integration (three paths)

### 1. Rails parameter filtering

`param_filters` returns a proc that ActiveSupport::ParameterFilter invokes as
`(key, value)`, mutating string values in place (ParameterFilter passes a dup,
so frozen originals are safe). Append it — keep your existing key-based filters:

```ruby
# config/initializers/filter_parameter_logging.rb
Rails.application.config.filter_parameters += DcodeRedaction.param_filters
```

### 2. Sentry event scrubbing (composition)

`sentry_scrub` mutates the Sentry **event object** in place and returns the same
object (never a Hash). It returns `nil` on internal error, dropping the event
(fail-closed). Compose it with any existing scrubber, short-circuiting on `nil`,
on **both** `before_send` and `before_send_transaction`:

```ruby
# config/initializers/sentry.rb
scrub = lambda do |event, hint|
  event = MyExistingScrubber.call(event, hint)  # if you have one
  return nil if event.nil?                        # respect an intentional drop
  DcodeRedaction.sentry_scrub(event)              # same event object back
end

config.before_send             = scrub
config.before_send_transaction = scrub
```

It covers the String leaves of: `message`, exception `values` (and stacktrace
frame `vars`), `breadcrumbs`, `request` (`url`/`query_string`/`data`/`headers`/
`cookies`/`env`), `extra`, `tags`, `contexts`, `user`, and transaction `spans`
(`description`/`data`/`tags`). Each of these is handled whether it arrives as an
attribute-style interface object or as a plain Hash (String **or** Symbol keys),
since some Sentry events (e.g. transaction `spans`) are already Hash-serialized
at build time. On a pathological (e.g. cyclic) structure it fails closed and
drops the event.

### 3. Log formatter wrapping

`wrap_formatter` prepends redaction onto the formatter's `call`, preserving the
formatter **object** — critical for `ActiveSupport::TaggedLogging`, whose tag
methods delegate to that object (replacing the formatter with a proc would break
tagging). Idempotent.

```ruby
# config/initializers/dcode_redaction.rb (production)
DcodeRedaction.wrap_formatter(Rails.logger)
```

**Broadcast loggers:** `ActiveSupport::BroadcastLogger` fans out to multiple
sink loggers, each with its own formatter. Wrap **each sink** individually:

```ruby
Rails.logger.broadcasts.each { |sink| DcodeRedaction.wrap_formatter(sink) }
```

## Design guarantees

- **Fail-closed.** A malformed pattern fails at `require` (patterns are compiled
  constants). An unexpected runtime error in `redact` returns `"[REDACTION_ERROR]"`
  — never the original text — and never logs internally (that would recurse).
  A URL that `URI.parse` rejects falls back **non-recursively** (secret passes +
  regex userinfo/query scrub), so it neither leaks nor kills the log line.
- **Marker protection.** Passes run in a fixed order and later passes skip
  already-inserted `[REDACTED:…]` markers, so a value keeps the label of the
  first pattern that matched it.
- **Low-cost gate.** A union of cheap anchor sub-expressions short-circuits
  no-secret text before any per-pattern work. Typical log lines redact in
  ~15 µs; see `bin/bench`.

## Known limitations

- **Unquoted, space-containing secret values are not redacted.** `password=abcd efgh`
  (no quotes) has no unambiguous end, so only the first whitespace-delimited token
  would be considered — and the assignment pattern requires an 8+ char run with no
  spaces. Quote such values (`password="abcd efgh ijkl mnop"`) and they are
  covered. Key-based filtering (path 1) also covers them by key name.
- **Content-based, not key-based.** `param_filters`/`sentry_scrub` redact values
  that *look* like secrets. A plaintext password stored under a `password` key is
  not secret-shaped and is not caught here — that is what your key-based
  `filter_parameters` list is for. Run both.
- **IPv6-literal host URLs** (`https://[::1]/…`) are not structurally parsed —
  the URL matcher excludes `[`/`]` to avoid folding surrounding log punctuation.
  Secret-shaped values in such URLs are still caught by the value passes
  (`sk-…`, `Bearer …`, `token=…`, JWTs); only a non-secret-shaped value under a
  URL-only sensitive key (`code`, `state`) in an IPv6-host URL can slip through.
- **Malformed URLs with percent-encoded sensitive key names.** The non-recursive
  fallback (used only when `URI.parse` rejects the URL) matches key names
  literally, so `?api%5Fkey=…` in a malformed URL is not decoded. Well-formed
  URLs decode keys before matching.
- Extremely large single strings pay a gate scan proportional to length; redaction
  targets log-line-sized inputs.

## Development

```bash
bundle install
bundle exec rspec   # full suite
bin/bench           # throughput on benign / adversarial / typical payloads
```

## License

MIT © Dcode
