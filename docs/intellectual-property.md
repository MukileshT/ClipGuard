# License, patents and trademarks

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

This document explains how the intellectual property of ClipWarden is handled.
It is meant for contributors, for companies that want to use ClipWarden, and
for anyone who wants to build on the code.

## The short version

| Aspect                     | Rule                                                              |
| -------------------------- | ----------------------------------------------------------------- |
| Source code                | Apache License 2.0, permissive, with an **express patent license** |
| Name "ClipWarden" and logo | Trademark of Mukilesh, not covered by the license (`TRADEMARK.md`) |
| Patents                    | This repository makes no patent claim; section 3 grants users a patent license for each contribution |
| Contributions              | Licensed under Apache-2.0 as well, signed off with the DCO        |

## Why Apache-2.0 and not MIT

Both licenses allow almost everything, but they differ in one important way:

- **MIT** has no express patent grant. It only mentions the right to deal in
  the software, which leaves the patent question open.
- **Apache-2.0 section 3** grants an *express patent license* from every
  contributor to every user, for the contributor's own contribution. If a user
  starts patent litigation claiming that the software infringes a patent, the
  patent licenses of that user end.

That express grant gives companies that embed the code more certainty about
patents than a bare copyright license does.

## Patents

A license is not a patent: the Apache-2.0 patent clause grants *users* a
license, and it does not create a patent for the author. ClipWarden does not
rely on patents.

The source is already public. If you want to patent an idea from this project,
talk to a patent attorney before disclosing more, because the rules for the
inventor's own earlier publication differ by country: the United States allows
a one-year grace period, the European Patent Office generally allows none, and
the Indian grace period is narrow and does not cover an ordinary publication.
In India, a computer program is patentable only when it has a technical effect
beyond the program itself (Patents Act, section 3(k)).

## Trademarks

"ClipWarden" and the shield artwork are trademarks of Mukilesh. The Apache
license covers the code, not the name (section 6 of the license):

- You may use the code, build on it, and distribute it under the terms of the
  license.
- You may **not** call your product "ClipWarden" or use the logo. Use a name
  of your own and say that it is based on ClipWarden.

The full policy is in [`TRADEMARK.md`](../TRADEMARK.md).

## Contributions

Every pull request is understood as a contribution of the code under the
Apache License 2.0, including the patent license of section 3. Commits carry a
`Signed-off-by` line (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)).
Contributors keep the copyright of their own work.

If a contribution should not be licensed that way, it has to be sent
privately and marked accordingly before it is merged.

## Reporting a vulnerability or an intellectual property issue

Report security issues privately through GitHub (**Security → Report a
vulnerability**), as described in [`SECURITY.md`](../SECURITY.md). For a
trademark or other intellectual property issue, open an issue on the
repository.
