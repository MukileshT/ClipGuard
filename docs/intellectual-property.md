# Patents and trademarks

<!-- Copyright 2026 Mukilesh -->
<!-- -->
<!-- Licensed under the Apache License, Version 2.0 (the "License"); -->
<!-- you may not use this file except in compliance with the License. -->
<!-- You may obtain a copy of the License at -->
<!-- -->
<!--     http://www.apache.org/licenses/LICENSE-2.0 -->
<!-- -->
<!-- Unless required by applicable law or agreed to in writing, software -->
<!-- distributed under the License is distributed on an "AS IS" BASIS, -->
<!-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. -->
<!-- See the License for the specific language governing permissions and -->
<!-- limitations under the License. -->


This document describes how the intellectual property of ClipWarden is
protected. It is meant for contributors, companies that want to use
ClipWarden, and for anyone who wants to build on the code.

## The short version

| Aspect              | Rule                                                            |
| ------------------- | --------------------------------------------------------------- |
| Source code         | Apache License 2.0 — permissive, with an **express patent licence** |
| Name "ClipWarden"    | Trademark of Mukilesh — not covered by the licence              |
| Patents             | The project may be patented; users receive the patent licence    |
| Contributions       | Contributed work is licensed under Apache-2.0 as well            |

## Why Apache-2.0 and not MIT

Both licences allow almost everything, but they differ in one important way:

- **MIT** grants no patent rights at all. It only covers copyright.
- **Apache-2.0 section 3** grants an *express patent licence* from every
  contributor to every user of the software. If a contributor later tries to
  sue a user of ClipWarden over a patent that covers their contribution, that
  patent licence ends for them.

For a security tool that companies embed in their own products, that patent
clause is the difference between "permissive" and "permissive and safe".

If your legal department prefers MIT or another permissive licence, the
project can be dual licensed (`Apache-2.0 OR MIT`) on request.

## Filing patents

**A licence is not a patent.** The Apache-2.0 patent clause grants the
*users* a patent licence; it does not create a patent for the author. To
protect the invention itself, a patent application has to be filed.

### Order matters — file before you publish

Patent rights are affected by public disclosure:

| Jurisdiction | Effect of publishing the source before filing |
| ------------ | --------------------------------------------- |
| India        | A 12-month grace period applies to a disclosure by the inventor |
| United States | A 1-year grace period applies to the inventor's own disclosure |
| Europe (EPO) | **No grace period** — a public disclosure can destroy the patent |

ClipWarden is published on GitHub, so this has to be planned deliberately:

1. **File first, publish later.** The safest order is: file the application,
   then publish. Everything in this repository can be published afterwards.
2. If the code is already public, file as soon as possible and rely on the
   grace period of the relevant jurisdiction — and keep a dated record of the
   first publication (the commit history of the repository is such a record).
3. Keep the invention secret until the filing is made. A public commit that
   explains the technical advantage in detail can weaken the claim in
   jurisdictions without a grace period.

### What can be patented

Not everything. In most jurisdictions software is patentable when the claim
covers a **technical effect** — something that runs faster, uses less
resources, or solves a technical problem in a way that is not obvious:

- ✅ the clipboard interception without a race between the copy and the paste
- ✅ the protection of the clipboard with a per-process fingerprint instead of
  the content itself
- ✅ the decision model that applies the policy of the foreground application
  at paste time
- ❌ "a program that detects API keys in text" — that is an abstract idea and
  is usually refused

A professional attorney should assess the claims. The documentation in this
repository (especially `docs/architecture.md`) describes the technical
approach in detail and is a good starting point for a patent disclosure.

### Practical steps

1. **Write a disclosure** — the problem, the technical solution, the
   advantages over the known approaches, and the date of the first public
   disclosure.
2. **File with the Indian Patent Office** (or through a patent attorney) as
   a provisional specification; a PCT application can follow if foreign
   protection is wanted.
3. **Keep the evidence** — the repository history, the release notes and the
   date of the first publication.
4. **Publish the patent** — Apache-2.0 already grants every user the patent
   licence, so no additional licence file is needed.

## Trademarks

"ClipWarden" and the shield artwork are trademarks of Mukilesh. The Apache
licence covers the code, not the name:

- You may use the code, build on it, and distribute it under the terms of the
  licence.
- You may **not** call your product "ClipWarden" or use the logo. Use a name
  of your own and say that it is based on ClipWarden.

The licence header of a source file does not restrict this; it only asks that
the notice is kept.

## Contributions

Every pull request is understood as a contribution of the code under the
Apache License 2.0, including the patent licence of section 3. Contributors
keep the copyright of their own work and grant the patent licence with it.

If a contribution should not be licensed that way, it has to be sent
privately and marked accordingly before it is merged.

## Reporting a vulnerability or an intellectual property issue

Please report security issues privately to the maintainers rather than in a
public issue tracker:

**Mukilesh — 145214507+MukileshT@users.noreply.github.com**

Include a description, the affected version and, if possible, a reproduction
that does not involve a real credential.