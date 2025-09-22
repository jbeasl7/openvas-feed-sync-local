# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885425");
  script_cve_id("CVE-2023-47627");
  script_tag(name:"creation_date", value:"2023-12-10 02:16:53 +0000 (Sun, 10 Dec 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-22 22:40:55 +0000 (Wed, 22 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-5130a73b00)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-5130a73b00");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-5130a73b00");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238879");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242220");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249825");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250615");
  script_xref(name:"URL", value:"https://docs.aiohttp.org/en/stable/client_advanced.html#character-set-detection");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/blob/v3.8.6/CHANGES.rst#386-2023-10-07");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-gfw2-4jvh-wgfg");
  script_xref(name:"URL", value:"https://github.com/aio-libs/aiohttp/security/advisories/GHSA-pjjw-qhg8-p2p9");
  script_xref(name:"URL", value:"https://pagure.io/fesco/issue/3106");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'llhttp, python-aiohttp, uxplay' package(s) announced via the FEDORA-2023-5130a73b00 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-47627

[link moved to references]

## python-aiohttp 3.8.6 (2023-10-07)

[link moved to references]

### Security bugfixes

- Upgraded `llhttp` to v9.1.3: [link moved to references]
- Updated Python parser to comply with RFCs 9110/9112: [link moved to references]

### Deprecation

- Added `fallback_charset_resolver` parameter in `ClientSession` to allow a user-supplied character set detection function. Character set detection will no longer be included in 3.9 as a default. If this feature is needed, please use [`fallback_charset_resolver`]([link moved to references]).

### Features

- Enabled lenient response parsing for more flexible parsing in the client (this should resolve some regressions when dealing with badly formatted HTTP responses).

### Bugfixes

- Fixed `PermissionError` when `.netrc` is unreadable due to permissions.
- Fixed output of parsing errors pointing to a `\n`.
- Fixed `GunicornWebWorker` max_requests_jitter not working.
- Fixed sorting in `filter_cookies` to use cookie with longest path.
- Fixed display of `BadStatusLine` messages from `llhttp`.

----

## llhttp 9.1.3

### Fixes

- Restart the parser on HTTP 100
- Fix chunk extensions quoted-string value parsing
- Fix lenient_flags truncated on reset
- Fix chunk extensions' parameters parsing when more then one name-value pair provided

## llhttp 9.1.2

### What's Changed

- Fix HTTP 1xx handling

## llhttp 9.1.1

### What's Changed

- feat: Expose new lenient methods

## llhttp 9.1.0

### What's Changed

- New lenient flag to make CR completely optional
- New lenient flag to have spaces after chunk header");

  script_tag(name:"affected", value:"'llhttp, python-aiohttp, uxplay' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"llhttp", rpm:"llhttp~9.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llhttp-debuginfo", rpm:"llhttp-debuginfo~9.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llhttp-debugsource", rpm:"llhttp-debugsource~9.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llhttp-devel", rpm:"llhttp-devel~9.1.3~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp", rpm:"python-aiohttp~3.8.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.8.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp+speedups", rpm:"python3-aiohttp+speedups~3.8.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp", rpm:"python3-aiohttp~3.8.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp-debuginfo", rpm:"python3-aiohttp-debuginfo~3.8.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uxplay", rpm:"uxplay~1.66~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uxplay-debuginfo", rpm:"uxplay-debuginfo~1.66~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uxplay-debugsource", rpm:"uxplay-debugsource~1.66~2.fc39", rls:"FC39"))) {
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
