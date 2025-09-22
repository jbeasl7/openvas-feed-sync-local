# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57173");
  script_cve_id("CVE-2005-4048", "CVE-2006-2802");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2006-207-04)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-207-04");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.391759");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xine-lib' package(s) announced via the SSA:2006-207-04 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xine-lib packages are available for Slackware 10.2 and -current to
fix security issues.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]

Evidently there is also an issue involving AVI files which has not
been issued a CVE entry.


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/xine-lib-1.1.2-i686-1.tgz:
 Upgraded to xine-lib-1.1.2.
 According to xinehq.de's announcement:
 There are three security fixes:
 - CVE-2005-4048: possible buffer overflow in libavcodec (crafted PNGs),
 - CVE-2006-2802: possible buffer overflow in the HTTP plugin,
 - possible buffer overflow via bad indexes in specially-crafted AVI files.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xine-lib' package(s) on Slackware 10.2, Slackware current.");

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

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"xine-lib", ver:"1.1.2-i686-1", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xine-lib", ver:"1.1.2-i686-1", rls:"SLKcurrent"))) {
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
