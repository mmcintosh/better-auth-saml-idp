# Third-party notices

This repository and the published package include the following third-party material. Everything else is covered by [LICENSE](LICENSE).

## libxml2 2.15.4, compiled into `wasm/xsd.wasm` (built in `wasm-validator/`)

Source: https://gitlab.gnome.org/GNOME/libxml2 (tarball sha256 `98087fd181d9070724f3fbc65c7377db03038eb92bd882374daff44940138821`). License, from the `Copyright` file of that release:

```
Except where otherwise noted in the source code (e.g. the files dict.c and
list.c, which are covered by a similar licence but with different Copyright
notices) all the files are:

 Copyright (C) 1998-2012 Daniel Veillard.  All Rights Reserved.
 Copyright (C) The Libxml2 Contributors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is fur-
nished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FIT-
NESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## OASIS SAML 2.0 schemas, in `schemas/` and `src/saml/schemas.generated.ts`

`saml-schema-protocol-2.0.xsd`, `saml-schema-assertion-2.0.xsd` and `saml-schema-metadata-2.0.xsd`, from https://docs.oasis-open.org/security/saml/v2.0/. Copyright © OASIS Open. All Rights Reserved.

The files in `schemas/` are unmodified. The generated TypeScript copy only rewrites `schemaLocation` URLs to local file names, so no network access is needed; see `scripts/build-schemas.mjs`. The full OASIS copyright and IPR notices are in the "Notices" section of the SAML 2.0 standard documents, e.g. https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf.

## W3C schemas, in `schemas/` and `src/saml/schemas.generated.ts`

- `xmldsig-core-schema.xsd` (XML Signature). Copyright 2001 The Internet Society and W3C (Massachusetts Institute of Technology, Institut National de Recherche en Informatique et en Automatique, Keio University). Licensed under the W3C Software License, http://www.w3.org/Consortium/Legal/copyright-software-19980720.
- `xenc-schema.xsd` (XML Encryption). Copyright © 2011 World Wide Web Consortium (Massachusetts Institute of Technology, European Research Consortium for Informatics and Mathematics, Keio University). Licensed under the W3C Software License, http://www.w3.org/Consortium/Legal/2002/copyright-software-20021231.
- `xml.xsd` (the XML namespace schema), from https://www.w3.org/2001/xml.xsd. Copyright © World Wide Web Consortium, W3C Software and Document License.

The files in `schemas/` are unmodified and keep their original notices. **Changes made in the generated copy** (`scripts/build-schemas.mjs`):
1. Absolute `schemaLocation` URLs are rewritten to local file names.
2. The DOCTYPE is removed from `xmldsig-core-schema.xsd` and `xenc-schema.xsd`. It declares entities the schemas don't use and references an external DTD. The script asserts both of these facts.

## better-auth-cloudflare, in `vendor/` (development and tests only; not shipped)

`vendor/better-auth-cloudflare-0.3.1-main-dbe08c51b.tgz` is a build of https://github.com/zpg6/better-auth-cloudflare at commit `dbe08c51b`, which is unreleased at the time of writing. MIT License, Copyright (c) 2025 Zach Grimaldi; the license is included inside the tarball.

## Spike code, in `spike/libxml2-vendor/` (Phase 0 evidence only; not shipped)

This is a patched copy of `libxml2-wasm` 0.7.2 (https://github.com/jameslan/libxml2-wasm, MIT, Copyright (c) 2023 James Lan; its LICENSE files are copied alongside) that also contains libxml2 (MIT, above). It exists to reproduce the workerd blocker recorded in DECISIONS.md D-003.
