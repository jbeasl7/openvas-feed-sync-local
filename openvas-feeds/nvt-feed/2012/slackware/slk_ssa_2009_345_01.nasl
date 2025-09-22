# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66518");
  script_cve_id("CVE-2009-1570", "CVE-2009-3909");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2009-345-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.1|12\.2|13\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2009-345-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.433860");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the SSA:2009-345-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New gimp packages are available for Slackware 12.1, 12.2, 13.0, and -current to
fix security issues.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]


Here are the details from the Slackware 13.0 ChangeLog:
+--------------------------+
patches/packages/gimp-2.6.8-i486-1_slack13.0.txz: Upgraded.
 This fixes integer overflows in the image handling plugins that could
 lead to the execution of arbitrary code or an application crash if a
 malicious image is loaded.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gimp' package(s) on Slackware 12.1, Slackware 12.2, Slackware 13.0, Slackware current.");

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

if(release == "SLK12.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"gimp", ver:"2.4.7-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"gimp", ver:"2.4.7-i486-2_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"gimp", ver:"2.6.8-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gimp", ver:"2.6.8-x86_64-1_slack13.0", rls:"SLK13.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gimp", ver:"2.6.8-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"gimp", ver:"2.6.8-x86_64-1", rls:"SLKcurrent"))) {
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
