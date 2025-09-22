# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1332.1");
  script_cve_id("CVE-2023-45288", "CVE-2024-6104", "CVE-2025-22868", "CVE-2025-22869", "CVE-2025-27144", "CVE-2025-30204");
  script_tag(name:"creation_date", value:"2025-04-21 04:06:46 +0000 (Mon, 21 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-26 17:19:40 +0000 (Wed, 26 Jun 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1332-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251332-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240468");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039053.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rekor' package(s) announced via the SUSE-SU-2025:1332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rekor fixes the following issues:

- CVE-2023-45288: rekor: golang.org/x/net/http2: Fixed close connections when receiving too many headers (bsc#1236519)
- CVE-2024-6104: rekor: hashicorp/go-retryablehttp: Fixed sensitive information disclosure inside log file (bsc#1227053)
- CVE-2025-22868: rekor: golang.org/x/oauth2/jws: Fixed unexpected memory consumption during token parsing (bsc#1239191)
- CVE-2025-22869: rekor: golang.org/x/crypto/ssh: Fixed denial of service in the Key Exchange (bsc#1239327)
- CVE-2025-27144: rekor: gopkg.in/go-jose/go-jose.v2,github.com/go-jose/go-jose/v4,github.com/go-jose/go-jose/v3: Fixed denial of service in Go JOSE's parsing (bsc#1237638)
- CVE-2025-30204: rekor: github.com/golang-jwt/jwt/v5: Fixed jwt-go allowing excessive memory allocation during header parsing (bsc#1240468)

Other fixes:

- Update to version 1.3.10:
 * Features
 - Added --client-signing-algorithms flag (#1974)
 * Fixes / Misc
 - emit unpopulated values when marshalling (#2438)
 - pkg/api: better logs when algorithm registry rejects a key
 (#2429)
 - chore: improve mysql readiness checks (#2397)
 - Added --client-signing-algorithms flag (#1974)

- Update to version 1.3.9 (jsc#SLE-23476):
 * Cache checkpoint for inactive shards (#2332)
 * Support per-shard signing keys (#2330)

- Update to version 1.3.8:
 * Bug Fixes
 - fix zizmor issues (#2298)
 - remove unneeded value in log message (#2282)
 * Quality Enhancements
 - chore: relax go directive to permit 1.22.x
 - fetch minisign from homebrew instead of custom ppa (#2329)
 - fix(ci): simplify GOVERSION extraction
 - chore(deps): bump actions pins to latest
 - Updates go and golangci-lint (#2302)
 - update builder to use go1.23.4 (#2301)
 - clean up spaces
 - log request body on 500 error to aid debugging (#2283)

- Update to version 1.3.7:
 * New Features
 - log request body on 500 error to aid debugging (#2283)
 - Add support for signing with Tink keyset (#2228)
 - Add public key hash check in Signed Note verification (#2214)
 - update Trillian TLS configuration (#2202)
 - Add TLS support for Trillian server (#2164)
 - Replace docker-compose with plugin if available (#2153)
 - Add flags to backfill script (#2146)
 - Unset DisableKeepalive for backfill HTTP client (#2137)
 - Add script to delete indexes from Redis (#2120)
 - Run CREATE statement in backfill script (#2109)
 - Add MySQL support to backfill script (#2081)
 - Run e2e tests on mysql and redis index backends (#2079)
 * Bug Fixes
 - remove unneeded value in log message (#2282)
 - Add error message when computing consistency proof (#2278)
 - fix validation error handling on API (#2217)
 - fix error in pretty-printed inclusion proof from verify
 subcommand (#2210)
 - Fix index scripts (#2203)
 - fix failing sharding test
 - Better error handling in backfill script (#2148)
 - Batch entries in cleanup script (#2158)
 - Add missing workflow for index cleanup test (#2121)
 - hashedrekord: fix schema $id (#2092)");

  script_tag(name:"affected", value:"'rekor' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"rekor", rpm:"rekor~1.3.10~150400.4.25.1", rls:"openSUSELeap15.6"))) {
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
