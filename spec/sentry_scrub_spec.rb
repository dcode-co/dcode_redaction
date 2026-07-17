# frozen_string_literal: true

# Duck-typed Sentry event doubles (Structs) so the gem needs no sentry gem.
module SentryDoubles
  Single      = Struct.new(:value, keyword_init: true)
  SingleTrace = Struct.new(:value, :stacktrace, keyword_init: true)
  Stacktrace  = Struct.new(:frames, keyword_init: true)
  Frame       = Struct.new(:vars, keyword_init: true)
  Exc         = Struct.new(:values, keyword_init: true)
  Crumb       = Struct.new(:message, :data, keyword_init: true)
  Breadcrumbs = Struct.new(:buffer, keyword_init: true)
  Req         = Struct.new(:url, :query_string, :data, :headers, :cookies, :env, keyword_init: true)
  # Error event intentionally has NO `spans` member.
  ErrorEvent  = Struct.new(:message, :exception, :breadcrumbs, :request,
                           :extra, :tags, :contexts, :user, keyword_init: true)
  Span        = Struct.new(:description, :data, :tags, keyword_init: true)
  TxnEvent    = Struct.new(:message, :request, :extra, :tags, :contexts,
                           :user, :spans, keyword_init: true)
end

RSpec.describe "DcodeRedaction.sentry_scrub" do
  include SentryDoubles
  fx = ->(*p) { p.join }
  let(:secret) { fx.call("xai-", "abc123XYZdef456GHIjkl789") }
  let(:marker) { "[REDACTED:api_key]" }

  it "returns nil when the event is nil (drop respected)" do
    expect(DcodeRedaction.sentry_scrub(nil)).to be_nil
  end

  context "error event" do
    let(:event) do
      SentryDoubles::ErrorEvent.new(
        message: fx.call("boom ", secret),
        exception: SentryDoubles::Exc.new(
          values: [SentryDoubles::Single.new(value: fx.call("raised ", secret))]
        ),
        breadcrumbs: SentryDoubles::Breadcrumbs.new(
          buffer: [SentryDoubles::Crumb.new(
            message: fx.call("crumb ", secret),
            data: { "arg" => secret }
          )]
        ),
        request: SentryDoubles::Req.new(
          url: fx.call("https://h.io/cb?api_key=", secret),
          query_string: fx.call("api_key=", secret),
          data: { "raw_body" => fx.call("password=", "hunter2hunter2") },
          headers: { "Authorization" => fx.call("Bearer ", "abcdefghij.klmnopqrst") },
          cookies: { "session" => secret }
        ),
        extra: { "nested" => { "k" => secret } },
        tags: { "t" => secret },
        contexts: { "c" => { "v" => secret } },
        user: { "token" => secret }
      )
    end

    it "returns the same object (not a Hash)" do
      result = DcodeRedaction.sentry_scrub(event)
      expect(result).to equal(event)
      expect(result).not_to be_a(Hash)
    end

    it "redacts every string leaf across all covered fields" do
      DcodeRedaction.sentry_scrub(event)
      expect(event.message).to include(marker)
      expect(event.exception.values[0].value).to include(marker)
      expect(event.breadcrumbs.buffer[0].message).to include(marker)
      expect(event.breadcrumbs.buffer[0].data["arg"]).to eq(marker)
      expect(event.request.url).not_to include("abc123XYZ")
      expect(event.request.query_string).not_to include("abc123XYZ")
      expect(event.request.data["raw_body"]).to eq("password=[REDACTED:assignment]")
      expect(event.request.headers["Authorization"]).to eq("Bearer [REDACTED:bearer]")
      expect(event.request.cookies["session"]).to eq(marker)
      expect(event.extra["nested"]["k"]).to eq(marker)
      expect(event.tags["t"]).to eq(marker)
      expect(event.contexts["c"]["v"]).to eq(marker)
      expect(event.user["token"]).to eq(marker)
    end
  end

  context "transaction event (spans)" do
    let(:event) do
      SentryDoubles::TxnEvent.new(
        message: nil,
        request: nil,
        extra: {},
        tags: {},
        contexts: {},
        user: { "id" => secret },
        spans: [SentryDoubles::Span.new(
          description: fx.call("GET ", secret),
          data: { "http.query" => secret }
        )]
      )
    end

    it "redacts span description and data and returns the same object" do
      result = DcodeRedaction.sentry_scrub(event)
      expect(result).to equal(event)
      expect(event.spans[0].description).to include(marker)
      expect(event.spans[0].data["http.query"]).to eq(marker)
      expect(event.user["id"]).to eq(marker)
    end
  end

  context "transaction event with Hash-shaped spans (logi real shape)" do
    # logi's TransactionEvent#spans is an Array of Hashes at build time
    # (finished_spans.map(&:to_hash)) — not attribute-style objects.
    it "redacts String leaves of Symbol-keyed Hash spans" do
      event = SentryDoubles::TxnEvent.new(
        message: nil, request: nil, extra: {}, tags: {}, contexts: {},
        user: {},
        spans: [{ description: fx.call("GET ", secret),
                  data: { "http.url" => fx.call("https://h.io/cb?api_key=", secret) },
                  op: "http.client" }]
      )
      result = DcodeRedaction.sentry_scrub(event)
      expect(result).to equal(event)
      expect(event.spans[0][:description]).to include(marker)
      expect(event.spans[0][:data]["http.url"]).not_to include("abc123XYZ")
      expect(event.spans[0][:op]).to eq("http.client")
    end

    it "redacts String leaves of String-keyed Hash spans" do
      event = SentryDoubles::TxnEvent.new(
        message: nil, request: nil, extra: {}, tags: {}, contexts: {},
        user: {},
        spans: [{ "description" => fx.call("query ", secret),
                  "data" => { "db.statement" => secret } }]
      )
      DcodeRedaction.sentry_scrub(event)
      expect(event.spans[0]["description"]).to include(marker)
      expect(event.spans[0]["data"]["db.statement"]).to eq(marker)
    end

    it "still handles attribute-style span objects" do
      event = SentryDoubles::TxnEvent.new(
        message: nil, request: nil, extra: {}, tags: {}, contexts: {},
        user: {},
        spans: [SentryDoubles::Span.new(description: fx.call("GET ", secret), data: {})]
      )
      DcodeRedaction.sentry_scrub(event)
      expect(event.spans[0].description).to include(marker)
    end
  end

  context "Hash-shaped breadcrumb" do
    it "redacts a breadcrumb delivered as a Hash" do
      event = SentryDoubles::ErrorEvent.new(
        message: nil, exception: nil,
        breadcrumbs: SentryDoubles::Breadcrumbs.new(
          buffer: [{ "message" => fx.call("crumb ", secret), "data" => { "k" => secret } }]
        ),
        request: nil, extra: {}, tags: {}, contexts: {}, user: {}
      )
      DcodeRedaction.sentry_scrub(event)
      expect(event.breadcrumbs.buffer[0]["message"]).to include(marker)
      expect(event.breadcrumbs.buffer[0]["data"]["k"]).to eq(marker)
    end
  end

  context "adjacent object-shaped fields (defense-in-depth)" do
    it "redacts object request env, object-span tags, and stacktrace frame vars" do
      event = SentryDoubles::ErrorEvent.new(
        message: nil,
        exception: SentryDoubles::Exc.new(values: [
          SentryDoubles::SingleTrace.new(
            value: fx.call("boom ", secret),
            stacktrace: SentryDoubles::Stacktrace.new(
              frames: [SentryDoubles::Frame.new(vars: { "local" => secret })]
            )
          )
        ]),
        breadcrumbs: nil,
        request: SentryDoubles::Req.new(
          url: nil, query_string: nil, data: nil, headers: nil, cookies: nil,
          env: { "HTTP_AUTHORIZATION" => fx.call("Bearer ", "abcdefghij.klmnopqrst") }
        ),
        extra: {}, tags: {}, contexts: {}, user: {}
      )
      DcodeRedaction.sentry_scrub(event)
      expect(event.request.env["HTTP_AUTHORIZATION"]).to eq("Bearer [REDACTED:bearer]")
      expect(event.exception.values[0].stacktrace.frames[0].vars["local"]).to eq(marker)
    end

    it "redacts object-span tags" do
      event = SentryDoubles::TxnEvent.new(
        message: nil, request: nil, extra: {}, tags: {}, contexts: {}, user: {},
        spans: [SentryDoubles::Span.new(description: nil, data: {}, tags: { "url" => secret })]
      )
      DcodeRedaction.sentry_scrub(event)
      expect(event.spans[0].tags["url"]).to eq(marker)
    end
  end

  context "breadcrumbs delivered as a serialized Hash" do
    it "deep-redacts a {\"values\" => [...]} breadcrumbs Hash" do
      event = SentryDoubles::ErrorEvent.new(
        message: nil, exception: nil,
        breadcrumbs: { "values" => [{ "message" => fx.call("crumb ", secret) }] },
        request: nil, extra: {}, tags: {}, contexts: {}, user: {}
      )
      DcodeRedaction.sentry_scrub(event)
      expect(event.breadcrumbs["values"][0]["message"]).to include(marker)
    end
  end

  context "fail-closed" do
    it "returns nil (drops the event) if scrubbing raises internally" do
      exploding = Object.new
      exploding.define_singleton_method(:message) { raise "kaboom" }
      expect(DcodeRedaction.sentry_scrub(exploding)).to be_nil
    end

    it "returns nil on a cyclic structure (stack overflow) rather than leaking" do
      cyclic = {}
      cyclic["self"] = cyclic
      event = SentryDoubles::ErrorEvent.new(
        message: nil, exception: nil, breadcrumbs: nil, request: nil,
        extra: cyclic, tags: {}, contexts: {}, user: {}
      )
      expect(DcodeRedaction.sentry_scrub(event)).to be_nil
    end
  end
end
