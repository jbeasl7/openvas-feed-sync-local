# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53938");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2004-111-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-111-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.372791");
  script_xref(name:"URL", value:"http://www.xinehq.de/index.php/security/XSA-2004-1");
  script_xref(name:"URL", value:"http://www.xinehq.de/index.php/security/XSA-2004-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xine' package(s) announced via the SSA:2004-111-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xine packages are available for Slackware 9.1 and -current to
fix security issues.

Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Tue Apr 20 19:01:58 PDT 2004
patches/packages/xine-lib-1rc3c-i686-1.tgz: Upgraded to xine-lib-1-rc3c.
 This release fixes a security problem where opening a malicious MRL
 could write to system (or other) files. For detailed information, see:
 [link moved to references]
 Thanks to Dario Nicodemi for the heads-up on this advisory.
 (* Security fix *)
patches/packages/xine-ui-0.99.1-i686-1.tgz: Upgraded to xine-ui-0.99.1,
 which fixes a similar MRL security issue. For details, see:
 [link moved to references]
 Thanks again to Dario Nicodemi.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xine' package(s) on Slackware 9.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"xine-lib", ver:"1rc3c-i686-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xine-ui", ver:"0.99.1-i686-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xine-lib", ver:"1rc3c-i686-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"xine-ui", ver:"0.99.1-i686-1", rls:"SLKcurrent"))) {
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
