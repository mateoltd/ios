---
name: evaluating-sdk-swift-updates
description: >
  Evaluate a bitwarden/ios "Update SDK to" / "SDK Update -" PR for compile-time, runtime, and
  serialization breaking changes by diffing the generated Swift bindings between the old and new
  pinned sdk-swift revisions, map affected symbols to iOS call sites, and resolve what is clearly in
  scope. Use when reviewing an SDK bump PR, a change to the `BitwardenSdk` revision in
  `project-common.yml`, or when triaging sdk-internal breaking changes on iOS. Trigger phrases:
  "evaluate the SDK update", "review the SDK bump", "check the SDK PR for breaking changes",
  "sdlc/sdk-update", "did the SDK break anything", "triage sdk-internal changes".
---

# Evaluating SDK Swift Updates — Bitwarden iOS

**Identify the whole surface before fixing anything — fixing the first break you find is not finishing.** Steps 1-6 always cover the entire commit range before Step 8 starts, no matter how obvious an early break looks. There is no compiler in this loop (see Step 8), so the completeness of the survey is the only thing standing between a bump and a broken `main`.

## What iOS actually pins

iOS does not pin `sdk-internal`. It pins a **`bitwarden/sdk-swift` git revision**, and that repo contains the **committed, generated UniFFI Swift bindings** — the exact source iOS compiles against. `sdk-internal` gitignores its generated Swift; its `release-swift.yml` copies `Sources/` into `sdk-swift` and commits it there. So the authoritative breaking-change signal is a diff of generated Swift, not a crawl of Rust. Use `sdk-internal` only to explain *why* something changed.

Four facts that shape every step below:

- **One flat module.** Every crate's bindings land in a single Swift target, `BitwardenSdk`. Kotlin gets one package per crate; Swift does not. A type moving between crates is an **import break on Android and a complete no-op on iOS** — never report it. Conversely, a new type whose name collides with an existing one is a Swift-only ambiguity error.
- **`sdk-swift`'s `main` is stale.** Release commits live on `unstable` and on `v<version>` tags; `main` is months behind. Never clone with `--depth` or `--branch main`.
- **Filenames vary in case.** The wrapper crate emits `BitwardenSDK.swift` (capital `SDK`) inside target `BitwardenSdk`, and crates without a `uniffi.toml` fall back to a snake_case crate name such as `bitwarden_importers.swift`. Never hardcode a file list.
- **Generated files carry heavy FFI plumbing.** `FfiConverter*`, `Uniffi*`, `_lift`, `_lower` are internal and never called by app code.

## Step 1: Read the pin from the PR

```bash
gh pr diff <PR> -R bitwarden/ios
```

Look for the removed and added `revision:` lines, e.g. `revision: 3dbc2724… # 3.0.0-7302-10ba9cb` → `revision: 58a710ee… # v3.0.0-7505-fbd2167`. The 40-char SHA is the **`sdk-swift`** revision; the trailing comment is the SDK version string, `<semver>-<ci-run-number>-<sdk-internal-short-sha>`.

That example is drawn from a real PR and the `v` on the new version is **the defect Step 6 checks for**, not the normal shape. A correct comment has no leading `v`.

Only two tracked files legitimately change in a pure bump: `project-common.yml` and `Bitwarden.xcworkspace/xcshareddata/swiftpm/Package.resolved`. Do not read the pin from `Package.resolved` — the bump script updates it with a blind `sed` and never recomputes `originHash`, so a stale `originHash` is expected and is **not** a finding. `BitwardenKit.xcodeproj/…/Package.resolved` also exists on disk, is untracked and generated, and is likewise **not** a finding.

## Step 2: Locate the sdk-swift clone

Check the directories next to this repo for a `sdk-swift` clone. In CI the workflow provides one as a sibling. If none exists, stop and tell the user it is a required prerequisite — do not clone it yourself.

A `sdk-internal` clone is optional and needed only for Step 4 and for Rust-level behavioral questions.

## Step 3: Diff the generated Swift surface

`sdk-surface-diff.sh`, next to this file, performs the comparison:

```bash
bash .claude/skills/evaluating-sdk-swift-updates/sdk-surface-diff.sh <sdk-swift-path> <old-rev> <new-rev>
```

It prints four sections:

- **RANGE** — the base commit plus every commit between the revisions, listed **oldest first**, so the last line is the newest commit. Each `sdk-swift` commit is 1:1 with an `sdk-internal` commit and records the full 40-char SHA and PR number in its subject, so the range needs no inference. The `base:` line exists because `OLD..NEW` excludes OLD, and the base subject is the only place the **old** `sdk-internal` SHA appears — Step 4 needs it.
- **REMOVED** — declaration names present at OLD and absent at NEW anywhere in the tree. These are hard compile breaks.
- **ADDED** — new declarations. Feed the `struct`/`enum`/`protocol`/`class` entries to the `--type` drill-down; `var`, `let` and `func` entries are members, which have no block of their own, so take those to `--decls` and find the owning type there. All of them feed Step 6.
- **MUTATED** — a type that survives while its declaration line changed: conformance and generic changes. Conformance drops live here and appear in **no** `*.rs` diff at all.

Then drill into any type flagged above, plus any type iOS constructs or switches on:

```bash
bash .claude/skills/evaluating-sdk-swift-updates/sdk-surface-diff.sh <sdk-swift-path> <old-rev> <new-rev> --type CipherView
```

That is where added enum cases, added record fields, changed optionality, and new protocol requirements show up.

Finally, run the whole-surface line diff. It is the **only** view that catches an argument label or return type change on a free function, or on a method of a type that no other section flagged — and Step 5 calls argument-label renames the highest-yield break:

```bash
bash .claude/skills/evaluating-sdk-swift-updates/sdk-surface-diff.sh <sdk-swift-path> <old-rev> <new-rev> --decls
```

Three properties of the output matter, and all are deliberate:

- **Everything is tree-wide and keyed by name, never per file.** Because the module is flat, a per-file diff is dominated by relocation noise — on a real 34-commit range, grepping deleted declarations per file surfaced roughly 15 apparent removals and *every one* was a type moving between generated files. Name-keyed tree-wide comparison removes that class of false positive by construction.
- **MUTATED covers type declarations only.** Type names are unique in the flat namespace, so joining on name is exact. Function names are not unique — `decrypt` alone is overloaded across many types — so joining functions on name would produce a meaningless cross product. Use `--type` for a type's members and `--decls` for everything else.
- **ADDED can mask a field addition.** It lists `<kind> <name>` pairs, so a field added to one type is invisible there if a field of that name already exists on any other type. `--decls` shows the declaration line instead and does reveal it. When it does, find the owning type and check whether the *owner* is new: a new field on a new type breaks nothing, whereas a new field on an existing record breaks every construction site.

## Step 4: Diff the bindings config, not just the Rust

`generate_codable_conformance` and `omit_checksums` are set per crate in `uniffi.toml` and appear in no `*.rs` diff. Only `bitwarden-core` and `bitwarden-crypto` opt into `Codable`, so a type that moves to a crate without that setting **silently loses `Codable`** — a real serialization break with no compile signal. If a `sdk-internal` clone is available:

```bash
git -C <sdk-internal-path> diff <old-internal-sha>..<new-internal-sha> -- '*/uniffi.toml'
```

Both SHAs come from Step 3's RANGE, which is ordered oldest first: the new one from the **last** commit subject listed, the old one from the `base:` line. Taking the new SHA from the wrong end truncates the range, which yields an empty `uniffi.toml` diff that reads as "no serialization change" — and nothing downstream would catch it.

Error enums come from `#[bitwarden_error(flat)]` in `bitwarden-error-macro`, **not** `derive(uniffi::Error)`. A grep for `uniffi::` alone misses every error-surface change.

## Step 5: Map every candidate to iOS call sites

A surface change is a **candidate**; only a call site makes it a **finding**. Grep the bare symbol name across the whole repo — do not restrict to a module list, and do not filter on an import prefix, since the flat module means every symbol arrives via plain `import BitwardenSdk`.

```bash
grep -rn '<Symbol>' --include='*.swift' .
```

Both apps consume the SDK and neither is optional to search: `BitwardenShared` (the bulk of consumers), `AuthenticatorShared`, `BitwardenKit`, `BitwardenSdkMocks`, `BitwardenAutoFillExtension`, and the `Bitwarden` app target.

For a **new protocol requirement** the symbol does not exist in the repo yet, so grep for the underlying *concept* instead. Check the hand-written conformers of `with_foreign` callback interfaces, which will not self-heal:

```bash
grep -rn 'Fido2CredentialStore\|ClientManagedTokens\|ServerCommunicationConfigRepository\|Fido2UserInterface' --include='*.swift' .
```

## Step 6: Check the iOS-specific gates

**The version comment is load-bearing.** `Scripts/generate-sdk-version-info.sh` greps it out of `project-common.yml` into a gitignored `SDKVersionInfo.swift`, and `BitwardenKit/Core/Platform/Utilities/SDKVersionInfoTests.swift` asserts the format with the anchored regex `^\d+\.\d+\.\d+-\d+-[a-f0-9]+$`.

```bash
grep -A3 'BitwardenSdk:' project-common.yml
```

Check the trailing comment against that regex. A leading `v` fails it and breaks the build — it comes from dispatching the bump with the `v`-prefixed **tag** name instead of the release name. Stripping the `v` is deterministic; fix it.

**`BitwardenSdkMocks` tracks the SDK's protocols by hand.** Sourcery cannot annotate external-module types, so `BitwardenSdkMocks/BitwardenSdkMocks.swift` declares one empty extension per SDK protocol under `// sourcery:file: AutoMockable`. The generated `AutoMockable.generated.swift` is gitignored, so a protocol rename or removal is a **compile error with zero diff evidence**, and the only reviewable artifact is that hand-maintained list.

```bash
grep -n 'extension ' BitwardenSdkMocks/BitwardenSdkMocks.swift
```

If Step 3 added a client protocol that iOS actually consumes, add `extension NewClientProtocol {}` to that file. If nothing consumes it yet, report it and leave it alone. Never hand-edit the generated mocks — they regenerate via `Scripts/generate-mocks.sh`.

## Step 7: Report

Cover all three outcomes, each with commit, symbol, and call sites: compile-time breaks, runtime and serialization considerations, and confirmed-safe. Report the safe conclusion explicitly — a bump where nothing broke still needs the audit trail.

Cite SDK commits and PRs as `bitwarden/sdk-internal#<N>` or a full commit URL. **Never a bare `#<N>`** copied from a commit subject: it auto-links within whatever repo the report is posted to and tags an unrelated `bitwarden/ios` PR.

## Step 8: Resolve

Decide the fix for anything found, **compile-time or runtime**, whenever the correct behavior is clear and within scope. Runtime findings are not automatically deferred; if the correct behavior is evident, fix it.

- **New required protocol method with no existing consumer:** stub it. An empty body with a `// no-op` comment, or a `nil`/default return that satisfies the compiler. That is a compilation decision, not a behavioral one.
- **Never stub with something that traps.** No `fatalError()`, no `preconditionFailure()`, no `try!`, no force-unwrap. Each turns a stub into a crash, which is worse than the compile error it replaces.
- **A sibling's structure is a template; its behavior is not evidence.** Copy naming, placement, and style from a neighbouring conformer. Do not infer storage, defaulting, error handling, or side effects from it.
- **When unsure, report instead of guessing**, along with anything needing a product decision.

Invoke `Skill(implementing-ios-code)` first if a fix is not purely mechanical, then commit with `Skill(bitwarden-delivery-tools:committing-changes)`.

**There is no compile step in this skill.** Generating the Xcode projects and building requires the full macOS toolchain, which the evaluation path deliberately does not carry — `.github/workflows/test.yml` already builds and tests every PR on a macOS runner and is the arbiter. Keep edits minimal and well understood, and record the reasoning for each one in the report so a human can audit it against the build result.

---

## Quick reference

| Observation | Meaning on iOS | Action |
|---|---|---|
| Name in REMOVED | Hard compile break | Map call sites, fix |
| Declaration missing from one file only | Type relocated in the flat module | **Not a finding** — ignore |
| Name in MUTATED | Conformance or generic change | Drill in with `--type`, then map call sites |
| Rust parameter renamed | Argument label changed — breaks every call site | Highest-yield break; only `--decls` shows it |
| Field added to a record | No `copy()` exists; every construction site must change | Find the owner: new owner is safe, existing owner breaks every construction site |
| Field addition absent from ADDED | That field name already exists on another type | Use `--decls`; ADDED keys on name, not declaration |
| Enum case added | Breaks exhaustive `switch` without `default` | Map `switch` sites only |
| Error case added | `Swift.Error` is untyped | Usually safe |
| Method added to a `with_foreign` protocol | Breaks hand-written conformers; mocks self-heal | Stub in conformers, leave mocks alone |
| `Codable` added or dropped | Serialization break, **no compile signal** | Check persistence sites |
| Type moved to a crate lacking `generate_codable_conformance` | Silent `Codable` loss | Check `uniffi.toml`, not `*.rs` |
| Version comment has a leading `v` | `SDKVersionInfoTests` fails | Strip the `v` |
| New client protocol absent from `BitwardenSdkMocks.swift` | Mock gap if iOS consumes it | Add the empty extension, or report |
| Script reports a revision not found | CI does a full clone, so the path or repo is wrong | Stop and report; do not fetch |
| Script reports no `Sources/BitwardenSdk` | Pointed at the `sdk-internal` clone by mistake | Use the `sdk-swift` path |
