# frozen_string_literal: true

# Public-repo hygiene: no contiguous secret-shaped literal may exist anywhere
# in the repository. We assert this by running every VALUE pattern over every
# tracked text file — a real credential shape would match. Fixtures are
# assembled at runtime, so the assembled shapes never appear as literals.
#
# Structural patterns (assignment / url / mcpkey_header) are intentionally
# excluded: they match `key=value`, `https://…`, `McpKey: …` shapes that
# legitimately appear in docs, examples, and tests and carry no credential
# material — matching them would flag ordinary prose, not leaked secrets.
RSpec.describe "source hygiene: no secret-shaped literals" do
  root = File.expand_path("..", __dir__)
  # FNM_DOTMATCH so dotfiles (.gitignore, .rspec) are covered too.
  files = Dir.glob(File.join(root, "**", "*"), File::FNM_DOTMATCH).select do |f|
    File.file?(f) && f !~ %r{/(?:vendor|\.git|\.bundle|pkg|tmp)/} && f !~ /\.gem\z/
  end

  structural = %i[assignment url mcpkey_header]
  value_passes = DcodeRedaction::Patterns::PASSES.reject { |p| structural.include?(p[:name]) }

  files.each do |file|
    rel = file.sub(root + "/", "")
    it "#{rel} contains no secret-shaped literal" do
      content = File.read(file, mode: "rb").force_encoding("UTF-8")
      skip "non-text file" unless content.valid_encoding?

      value_passes.each do |pass|
        match = content.match(pass[:regex])
        expect(match).to be_nil,
          "possible #{pass[:name]} secret literal in #{rel}: #{match && match[0][0, 40].inspect}"
      end
    end
  end
end
