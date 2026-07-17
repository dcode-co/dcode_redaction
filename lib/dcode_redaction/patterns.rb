# frozen_string_literal: true

module DcodeRedaction
  # Compiled secret patterns and the low-cost union gate.
  #
  # All regexes are module constants, so a malformed pattern fails at
  # `require` time (fail-fast) rather than at first redaction.
  #
  # Substitution order is fixed and load-bearing:
  #   PEM -> prefix families -> Dcode families -> bearer -> jwt -> url -> assignment
  # PEM runs first so no later pattern folds part of a key body; the marker-
  # producing passes (assignment value, url query value) carry a
  # `(?!\[REDACTED:)` guard so an already-substituted marker keeps its original
  # label instead of being clobbered by a later, less-specific pass.
  module Patterns
    # --- grok-derived patterns (10) --------------------------------------

    # Vendor API keys with `sk-`/`sk_` prefixes and xAI (`xai-`) keys.
    # `\b`-anchored so `task-`/`disk-`/`risk-` don't fold a stray `sk-`.
    API_KEY_PREFIX = /\b(?:sk[-_]|xai-)[A-Za-z0-9_-]{20,}/

    # AWS long-term (`AKIA`) and temporary (`ASIA`) access-key IDs.
    AWS_ACCESS_KEY = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/

    # GitHub PATs: classic (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) + fine-grained.
    GITHUB_TOKEN = /\b(?:gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/

    # GitLab (`glpat-`) and Slack (`xoxa-`/`xoxb-`/`xoxp-`/`xapp-`) tokens.
    VENDOR_TOKEN = /\b(?:glpat-|xox[abp]-|xapp-)[A-Za-z0-9-]{10,}/

    # Google API keys (`AIza` + 35 chars).
    GOOGLE_API_KEY = /\bAIza[0-9A-Za-z_-]{35}/

    # PEM private-key block (any key type), base64 body included.
    # Rust `(?s)` dot-all becomes Ruby `/m` so `.` spans the newline body.
    PEM_PRIVATE_KEY =
      /-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/m

    # `Bearer <token>` — scheme preserved on replacement. No terminal `\b`: the
    # char class already bounds the match, and a trailing `\b` would fail (and
    # under-redact) for a token whose last char is `-`/`.` (non-word).
    BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._-]{16,}/i

    # Bare JWT (`eyJ...header.payload.signature`) with no prefix. The three
    # 8+-char segments make base64 false positives unlikely. No terminal `\b`
    # (a `-`/`_`-terminated signature segment must still redact fully).
    JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/

    # Secret assignment: `<key><delim><value>`, 8-char value floor.
    # Two value branches, both marker-guarded:
    #   quoted   — `"..."`/`'...'`, may contain spaces (covers app passwords)
    #   unquoted — stops at whitespace/quote/comma/ampersand (grok shape)
    # Rust `$1$2$3` replacement becomes a Ruby block (see redaction passes).
    ASSIGNMENT = /
      \b(
          api[_-]?key
        | (?:access|refresh|id)[_-]token
        | token
        | secret
        | client[_-]secret
        | password
      )\b
      (\s*[:=]\s*)
      (?:
          # quoted: excludes ONLY the matching opening quote (\3), so a
          # single-quoted value may contain double quotes and vice versa.
          (["'])(?!\[REDACTED:)(?:(?!\3)[^\r\n]){8,}\3
        |
          (?!["'])(?!\[REDACTED:)[^\s"',&]{8,}
      )
    /ix

    # --- Dcode-derived patterns (6) --------------------------------------

    RENDER_API_KEY     = /\brnd_[A-Za-z0-9]{16,}\b/
    LOGI_PAK           = /\blogi_pak_[A-Za-z0-9]{8}_[A-Za-z0-9]{32}\b/
    LOGI_MCP_TOKEN     = /\bmcp_[A-Za-z0-9]{32}\b/
    LOGI_CLIENT_SECRET = /\blogi_secret_[0-9a-f]{64}\b/
    # No terminal `\b` (a `-`/`_`-terminated 35th char must still redact).
    TELEGRAM_BOT_TOKEN = /\b\d{8,10}:AA[A-Za-z0-9_-]{33}/

    # McpKey header/JSON/hash-rocket forms: `McpKey: x`, `"McpKey"=>"x"`,
    # `McpKey x`. Separator is horizontal whitespace only (`[ \t]`, never `\s`)
    # so it cannot bleed onto the next log line's unrelated identifier. The
    # `McpKey` + separator prefix is captured so only the token is redacted.
    MCPKEY_HEADER = /(\bMcpKey\b["' \t:=>]{1,6})(?!\[REDACTED:)[A-Za-z0-9._-]{16,}/i

    # --- URL sensitive query parameters (17 = grok 16 + mcp_key) ---------

    SENSITIVE_QUERY_PARAMS = %w[
      access_token
      api_key
      assertion
      auth
      client_secret
      code
      code_verifier
      id_token
      key
      password
      refresh_token
      requested_token
      session_id
      state
      subject_token
      token
      mcp_key
    ].freeze

    # URL, excluding trailing punctuation so surrounding brackets/backticks in
    # log text don't fold into the match. Case-insensitive scheme (so `HTTPS://`
    # is caught). The `\[REDACTED:...\]` alternation lets the match SPAN an
    # already-inserted marker inside the query, so an earlier pass's `[` does
    # not truncate the URL and orphan a later sensitive parameter (which the
    # structural scrub / fallback would then miss).
    URL = %r{https?://(?:\[REDACTED:[a-z_]+\]|[^\s"'<>(){}\[\],;`])+}i

    # Fallback query scrub for malformed URLs (non-recursive): `[?&#]key=value`
    # with the sensitive-param alternation, marker-guarded.
    QUERY_PARAM_SCRUB = Regexp.new(
      "([?&#])(" + SENSITIVE_QUERY_PARAMS.map { |p| Regexp.escape(p) }.join("|") +
        ")=(?!\\[REDACTED:)([^&#\\s\"'<>]+)",
      Regexp::IGNORECASE
    )

    # Userinfo in a URL authority: `://user:pass@` -> `://[REDACTED:userinfo]@`.
    USERINFO = %r{://[^/@\s]+@}

    # --- Ordered substitution passes (16) --------------------------------
    # kind: :simple           -> whole match becomes [REDACTED:<name>]
    #       :simple_capture   -> keep captured group 1, redact the rest
    #       :bearer           -> `Bearer [REDACTED:bearer]`
    #       :url              -> structural URL redaction
    #       :assignment       -> key+delim(+quotes) preserved, value redacted
    PASSES = [
      { name: :pem,                kind: :simple,         regex: PEM_PRIVATE_KEY },
      { name: :api_key,            kind: :simple,         regex: API_KEY_PREFIX },
      { name: :aws,                kind: :simple,         regex: AWS_ACCESS_KEY },
      { name: :github,             kind: :simple,         regex: GITHUB_TOKEN },
      { name: :vendor,             kind: :simple,         regex: VENDOR_TOKEN },
      { name: :google,             kind: :simple,         regex: GOOGLE_API_KEY },
      { name: :render_api_key,     kind: :simple,         regex: RENDER_API_KEY },
      { name: :logi_pak,           kind: :simple,         regex: LOGI_PAK },
      { name: :logi_mcp_token,     kind: :simple,         regex: LOGI_MCP_TOKEN },
      { name: :logi_client_secret, kind: :simple,         regex: LOGI_CLIENT_SECRET },
      { name: :telegram_bot_token, kind: :simple,         regex: TELEGRAM_BOT_TOKEN },
      { name: :mcpkey_header,      kind: :simple_capture, regex: MCPKEY_HEADER },
      { name: :bearer,             kind: :bearer,         regex: BEARER_TOKEN },
      { name: :jwt,                kind: :simple,         regex: JWT },
      { name: :url,                kind: :url,            regex: URL },
      { name: :assignment,         kind: :assignment,     regex: ASSIGNMENT }
    ].freeze

    # Low-cost union gate: cheap anchor sub-expressions, one per pass. Each
    # anchor is a strict superset (prefix) of its full pattern, so
    # "full pattern matches => gate matches" holds for every input (verified by
    # the implication spec). The gate is a performance filter, not a
    # correctness guarantee.
    GATE_ANCHORS = [
      /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
      /\b(?:sk[-_]|xai-)/,
      /\b(?:AKIA|ASIA)/,
      /\b(?:gh[opusr]_|github_pat_)/,
      /\b(?:glpat-|xox[abp]-|xapp-)/,
      /\bAIza/,
      /\brnd_/,
      /\blogi_pak_/,
      /\bmcp_/,
      /\blogi_secret_/,
      /\b\d{8,10}:AA/,
      /\bMcpKey\b/i,
      /\bBearer\s/i,
      /\beyJ/,
      %r{https?://}i,
      %r{\b(?:api[_-]?key|(?:access|refresh|id)[_-]token|token|secret|client[_-]secret|password)\b\s*[:=]}i
    ].freeze

    GATE = Regexp.union(*GATE_ANCHORS)

    # Tripwire enforced at load: pass count == gate anchors == 16. Adding a
    # pattern without adding its pass and gate anchor fails the require.
    PATTERN_COUNT = 16
    unless PASSES.length == PATTERN_COUNT &&
           GATE_ANCHORS.length == PATTERN_COUNT &&
           PASSES.map { |p| p[:name] }.uniq.length == PATTERN_COUNT
      raise "DcodeRedaction pattern-count drift: passes=#{PASSES.length} " \
            "anchors=#{GATE_ANCHORS.length} expected=#{PATTERN_COUNT}"
    end
  end
end
