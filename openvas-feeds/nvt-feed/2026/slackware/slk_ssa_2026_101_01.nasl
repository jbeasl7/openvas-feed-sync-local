# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.101.01");
  script_cve_id("CVE-2026-28387", "CVE-2026-28388", "CVE-2026-28389", "CVE-2026-28390");
  script_tag(name:"creation_date", value:"2026-04-13 05:04:32 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2026-101-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-101-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.490740");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/#CVE-2026-28387");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/#CVE-2026-28388");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/#CVE-2026-28389");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/#CVE-2026-28390");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-28387");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-28388");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-28389");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-28390");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SSA:2026-101-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssl packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/openssl-1.1.1zg-i586-1_slack15.0.txz: Upgraded.
 Apply patch to fix the following security issues:
 Potential Use-after-free in DANE Client Code.
 NULL Pointer Dereference When Processing a Delta CRL.
 Possible NULL Dereference When Processing CMS KeyAgreeRecipientInfo.
 Possible NULL Dereference When Processing CMS KeyTransportRecipientInfo.
 These CVEs were fixed by the 1.1.1zg release that is only available to
 subscribers to OpenSSL's premium extended support. The patch was prepared
 by backporting from the OpenSSL-3.0 repo.
 Thanks to Ken Zalewski for the patch!
 For more information, see:
 [links moved to references]
 (* Security fix *)
patches/packages/openssl-solibs-1.1.1zg-i586-1_slack15.0.txz: Upgraded.
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1zg-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.1.1zg-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1zg-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.1.1zg-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"3.5.6-i686-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"3.5.6-x86_64-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"3.5.6-i686-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"3.5.6-x86_64-2", rls:"SLKcurrent"))) {
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
