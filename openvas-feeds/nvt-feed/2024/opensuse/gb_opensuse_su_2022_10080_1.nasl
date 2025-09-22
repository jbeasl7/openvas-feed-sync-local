# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833484");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-34037");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 20:16:25 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:42:11 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for caddy (openSUSE-SU-2022:10080-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10080-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GQURFVT45F4OXOLLGP52CDBSBPTC2M4G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'caddy'
  package(s) announced via the openSUSE-SU-2022:10080-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for caddy fixes the following issues:
  Update to version 2.5.2:

  * admin: expect quoted ETags (#4879)

  * headers: Only replace known placeholders (#4880)

  * reverseproxy: Err 503 if all upstreams unavailable

  * reverseproxy: Adjust new TLS Caddyfile directive names (#4872)

  * fileserver: Use safe redirects in file browser

  * admin: support ETag on config endpoints (#4579)

  * caddytls: Reuse issuer between PreCheck and Issue (#4866)

  * admin: Implement /adapt endpoint (close #4465) (#4846)

  * forwardauth: Fix case when `copy_headers` is omitted (#4856)

  * Expose several Caddy HTTP Matchers to the CEL Matcher (#4715)

  * reverseproxy: Fix double headers in response handlers (#4847)

  * reverseproxy: Fix panic when TLS is not configured (#4848)

  * reverseproxy: Skip TLS for certain configured ports (#4843)

  * forwardauth: Support renaming copied headers, block support (#4783)

  * Add comment about xcaddy to main

  * headers: Support wildcards for delete ops (close #4830) (#4831)

  * reverseproxy: Dynamic ServerName for TLS upstreams (#4836)

  * reverseproxy: Make TLS renegotiation optional

  * reverseproxy: Add renegotiation param in TLS client (#4784)

  * caddyhttp: Log error from CEL evaluation (fix #4832)

  * reverseproxy: Correct the `tls_server_name` docs (#4827)

  * reverseproxy: HTTP 504 for upstream timeouts (#4824)

  * caddytls: Make peer certificate verification pluggable (#4389)

  * reverseproxy: api: Remove misleading 'healthy' value

  * Fix #4822 and fix #4779

  * reverseproxy: Add --internal-certs CLI flag #3589 (#4817)

  * ci: Fix build caching on Windows (#4811)

  * templates: Add `humanize` function (#4767)

  * core: Micro-optim in run() (#4810)

  * httpcaddyfile: Add `{err.*}` placeholder shortcut (#4798)

  * templates: Documentation consistency (#4796)

  * chore: Bump quic-go to v0.27.0 (#4782)

  * reverseproxy: Support http1.1 h2c (close #4777) (#4778)

  * rewrite: Handle fragment before query (fix #4775) [boo#1201822,
       CVE-2022-34037]

  * httpcaddyfile: Support multiple values for `default_bind` (#4774)");

  script_tag(name:"affected", value:"'caddy' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.5.2~bp154.2.8.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.5.2~bp154.2.8.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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