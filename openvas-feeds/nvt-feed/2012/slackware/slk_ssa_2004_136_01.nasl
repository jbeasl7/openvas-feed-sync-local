# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53930");
  script_cve_id("CVE-2004-0226", "CVE-2004-0231", "CVE-2004-0232");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2004-136-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-136-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.386678");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mc' package(s) announced via the SSA:2004-136-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mc packages are available for Slackware 9.0, 9.1, and -current to
fix security issues that These could lead to a denial of service or the
execution of arbitrary code as the user running mc.

Sites that use mc should upgrade to the new mc package.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]

Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Fri May 14 15:11:37 PDT 2004
patches/packages/mc-4.6.0-i486-2.tgz: Patched to fix buffer overflow,
 format string, and temporary file creation vulnerabilities found by
 Andrew V. Samoilov and Pavel Roskin. These could lead to a denial of
 service or the execution of arbitrary code as the user running mc.
 For more details, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mc' package(s) on Slackware 9.1, Slackware current.");

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

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"mc", ver:"4.6.0-i386-2", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mc", ver:"4.6.0-i486-2", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mc", ver:"4.6.0-i486-2", rls:"SLKcurrent"))) {
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
