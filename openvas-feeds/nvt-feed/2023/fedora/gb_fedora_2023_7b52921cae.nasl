# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885143");
  script_cve_id("CVE-2023-38552", "CVE-2023-39331", "CVE-2023-39332", "CVE-2023-39333", "CVE-2023-44487", "CVE-2023-45143");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:08 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-25 17:39:44 +0000 (Wed, 25 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-7b52921cae)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-7b52921cae");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-7b52921cae");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/0ccd4638ac");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/0e686d096b");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/14ece0aa76");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/17a05b141d");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/1beefd5f16");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/32d4d29d02");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/4e578f8ab1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/69e4218772");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/7b6a73172f");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/7c5e322346");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/80b342cc38");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/9fd67fbff0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/a5dd057540");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/commit/b0ce78a75b");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/48510");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49279");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49597");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49614");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49647");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49662");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49683");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49690");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49725");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49745");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49753");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49834");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/pull/49874");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/october-2023-security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20' package(s) announced via the FEDORA-2023-7b52921cae advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## 2023-10-13, Version 20.8.1 (Current), @RafaelGSS

This is a security release.

### Notable Changes

The following CVEs are fixed in this release:

* [CVE-2023-44487]([link moved to references]): `nghttp2` Security Release (High)
* [CVE-2023-45143]([link moved to references]): `undici` Security Release (High)
* [CVE-2023-39332]([link moved to references]): Path traversal through path stored in Uint8Array (High)
* [CVE-2023-39331]([link moved to references]): Permission model improperly protects against path traversal (High)
* [CVE-2023-38552]([link moved to references]): Integrity checks according to policies can be circumvented (Medium)
* [CVE-2023-39333]([link moved to references]): Code injection via WebAssembly export names (Low)

More detailed information on each of the vulnerabilities can be found in [October 2023 Security Releases]([link moved to references]) blog post.

----

## 2023-09-28, Version 20.8.0 (Current), @ruyadorno

### Notable Changes

#### Stream performance improvements

Performance improvements to writable and readable streams, improving the creation and destruction by +-15% and reducing the memory overhead each stream takes in Node.js

Contributed by Benjamin Gruenbaum in [#49745]([link moved to references]) and Raz Luvaton in [#49834]([link moved to references]).

Performance improvements for readable webstream, improving readable stream async iterator consumption by +-140% and improving readable stream `pipeTo` consumption by +-60%

Contributed by Raz Luvaton in [#49662]([link moved to references]) and [#49690]([link moved to references]).

#### Rework of memory management in `vm` APIs with the `importModuleDynamically` option

This rework addressed a series of long-standing memory leaks and use-after-free issues in the following APIs that support `importModuleDynamically`:

* `vm.Script`
* `vm.compileFunction`
* `vm.SyntheticModule`
* `vm.SourceTextModule`

This should enable affected users (in particular Jest users) to upgrade from older versions of Node.js.

Contributed by Joyee Cheung in [#48510]([link moved to references]).

#### Other notable changes

* \[[`32d4d29d02`]([link moved to references])] - **deps**: add v8::Object::SetInternalFieldForNodeCore() (Joyee Cheung) [#49874]([link moved to references])
* \[[`0e686d096b`]([link moved to references])] - **doc**: deprecate `fs.F_OK`, `fs.R_OK`, `fs.W_OK`, `fs.X_OK` (Livia Medeiros) [#49683]([link moved to references])
* \[[`a5dd057540`]([link moved to references])] - **doc**: deprecate `util.toUSVString` (Yagiz Nizipli) [#49725]([link moved to references])
* \[[`7b6a73172f`]([link moved to references])] - **doc**: deprecate calling `promisify` on a function that returns a promise (Antoine du Hamel) [#49647]([link moved to references])
* \[[`1beefd5f16`]([link moved to references])] - **esm**: set all hooks as release candidate (Geoffrey Booth) [#49597]([link moved to references])
* ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'nodejs20' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-debuginfo", rpm:"nodejs-debuginfo~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-full-i18n", rpm:"nodejs-full-i18n~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs-debuginfo", rpm:"nodejs-libs-debuginfo~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-npm", rpm:"nodejs-npm~10.1.0~1.20.8.1.1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debuginfo", rpm:"nodejs20-debuginfo~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debugsource", rpm:"nodejs20-debugsource~20.8.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-11.3-devel", rpm:"v8-11.3-devel~11.3.244.8~1.20.8.1.1.fc39", rls:"FC39"))) {
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
