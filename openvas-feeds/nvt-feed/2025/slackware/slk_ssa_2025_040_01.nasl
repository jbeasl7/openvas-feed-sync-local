# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.040.01");
  script_cve_id("CVE-2024-13176");
  script_tag(name:"creation_date", value:"2025-02-10 04:08:40 +0000 (Mon, 10 Feb 2025)");
  script_version("2025-02-10T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-02-10 05:38:01 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2025-040-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-040-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.481043");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-13176");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SSA:2025-040-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssl packages are available for Slackware 15.0 and -current to
fix a security issue.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/openssl-1.1.1zb_p2-i586-1_slack15.0.txz: Upgraded.
 Apply patch to fix a low severity security issue:
 Fix timing side-channel in ECDSA signature computation.
 There is a timing signal of around 300 nanoseconds when the top word of
 the inverted ECDSA nonce value is zero. This can happen with significant
 probability only for some of the supported elliptic curves. In particular
 the NIST P-521 curve is affected. To be able to measure this leak, the
 attacker process must either be located in the same physical computer or
 must have a very fast network connection with low latency.
 This CVE was fixed by the second 1.1.1zb release that is only available to
 subscribers to OpenSSL's premium extended support. The patch was prepared
 by backporting from the OpenSSL-3.0 repo.
 Thanks to Ken Zalewski for the patch!
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/openssl-solibs-1.1.1zb_p2-i586-1_slack15.0.txz: Upgraded.
+--------------------------+");

  script_tag(name:"affected", value:"'openssl' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1zb_p2-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1zb_p2-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1zb_p2-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1zb_p2-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssl11", ver:"1.1.1zb_p2-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl11", ver:"1.1.1zb_p2-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl11-solibs", ver:"1.1.1zb_p2-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl11-solibs", ver:"1.1.1zb_p2-x86_64-1", rls:"SLKcurrent"))) {
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
