# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.155.02");
  script_cve_id("CVE-2024-12718", "CVE-2025-4138", "CVE-2025-4330", "CVE-2025-4435", "CVE-2025-4517");
  script_tag(name:"creation_date", value:"2025-06-05 04:14:58 +0000 (Thu, 05 Jun 2025)");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2025-155-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-155-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.405275");
  script_xref(name:"URL", value:"https://pythoninsider.blogspot.com/2025/06/python-3134-31211-31113-31018-and-3923.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-12718");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-4138");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-4330");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-4435");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-4517");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the SSA:2025-155-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New python3 packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/python3-3.9.23-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 gh-135034: [CVE-2024-12718] [CVE-2025-4138] [CVE-2025-4330] [CVE-2025-4435]
 [CVE-2025-4517] Fixes multiple issues that allowed tarfile extraction filters
 (filter='data' and filter='tar') to be bypassed using crafted symlinks and
 hard links.
 gh-133767: Fix use-after-free in the 'unicode-escape' decoder with a
 non-'strict' error handler.
 gh-128840: Short-circuit the processing of long IPv6 addresses early in
 ipaddress to prevent excessive memory consumption and a minor denial-of-service.
 gh-80222: Folding of quoted string in display_name violates RFC.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'python3' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.23-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.9.23-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.12.11-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"python3", ver:"3.12.11-x86_64-1", rls:"SLKcurrent"))) {
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
