# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886751");
  script_cve_id("CVE-2024-27982", "CVE-2024-27983");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:27 +0000 (Mon, 27 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-2ffe03eaa6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2ffe03eaa6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2ffe03eaa6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257692");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272764");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273045");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273542");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274380");
  script_xref(name:"URL", value:"https://github.com/nodejs-private/node-private/pull/557");
  script_xref(name:"URL", value:"https://github.com/nodejs-private/node-private/pull/561");
  script_xref(name:"URL", value:"https://github.com/nodejs-private/node-private/pull/576");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/5e34540a96");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/ba1ae6d188");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/bd8f10a257");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/50453");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/50758");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/50960");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/51044");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/51045");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/51183");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/51244");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/51476");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/51850");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20' package(s) announced via the FEDORA-2024-2ffe03eaa6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## 2024-04-03, Version 20.12.1 'Iron' (LTS), @RafaelGSS

This is a security release

### Notable Changes

* CVE-2024-27983 - Assertion failed in node::http2::Http2Session::\~Http2Session() leads to HTTP/2 server crash- (High)
* CVE-2024-27982 - HTTP Request Smuggling via Content Length Obfuscation - (Medium)
* llhttp version 9.2.1
* undici version 5.28.4

### Commits

* \[[`bd8f10a257`]([link moved to references])] - **deps**: update undici to v5.28.4 (Matteo Collina) [nodejs-private/node-private#576]([link moved to references])
* \[[`5e34540a96`]([link moved to references])] - **http**: do not allow OBS fold in headers by default (Paolo Insogna) [nodejs-private/node-private#557]([link moved to references])
* \[[`ba1ae6d188`]([link moved to references])] - **src**: ensure to close stream when destroying session (Anna Henningsen) [nodejs-private/node-private#561]([link moved to references])

----

## 2024-04-03, Version 20.12.1 'Iron' (LTS), @RafaelGSS

This is a security release

### Notable Changes

* CVE-2024-27983 - Assertion failed in node::http2::Http2Session::\~Http2Session() leads to HTTP/2 server crash- (High)
* CVE-2024-27982 - HTTP Request Smuggling via Content Length Obfuscation - (Medium)
* llhttp version 9.2.1
* undici version 5.28.4


----

## 2024-03-26, Version 20.12.0 'Iron' (LTS), @richardlau

### Notable Changes

#### crypto: implement crypto.hash()

This patch introduces a helper crypto.hash() that computes
a digest from the input at one shot. This can be 1.2-2x faster
than the object-based createHash() for smaller inputs (<= 5MB)
that are readily available (not streamed) and incur less memory
overhead since no intermediate objects will be created.

```js
const crypto = require('node:crypto'),

// Hashing a string and return the result as a hex-encoded string.
const string = 'Node.js',
// 10b3493287f831e81a438811a1ffba01f8cec4b7
console.log(crypto.hash('sha1', string)),
```

Contributed by Joyee Cheung in [#51044]([link moved to references]).

#### Loading and parsing environment variables

* `process.loadEnvFile(path)`:
 * Use this function to load the `.env` file. If no path is specified, it automatically loads the .env file in the current directory. Example: `process.loadEnvFile()`.
 * Load a specific .env file by specifying its path. Example: `process.loadEnvFile('./development.env')`.

* `util.parseEnv(content)`:
 * Use this function to parse an existing string containing environment variable assignments.
 * Example usage: `require('node:util').parseEnv('HELLO=world')`.

Contributed by Yagiz Nizipli in [#51476]([link moved to references]).

#### New connection attempt events

Three new events were added in the `net.createConnection` flow:

* `connectionAttempt`: Emitted when a new connection attempt is established. In case of Happy Eyeballs, this might emitted multiple times.
* `connectionAttemptFailed`: Emitted when a connection attempt failed. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'nodejs20' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-debuginfo", rpm:"nodejs-debuginfo~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-full-i18n", rpm:"nodejs-full-i18n~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs-debuginfo", rpm:"nodejs-libs-debuginfo~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-npm", rpm:"nodejs-npm~10.5.0~1.20.12.2.1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debuginfo", rpm:"nodejs20-debuginfo~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debugsource", rpm:"nodejs20-debugsource~20.12.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-11.3-devel", rpm:"v8-11.3-devel~11.3.244.8~1.20.12.2.1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
