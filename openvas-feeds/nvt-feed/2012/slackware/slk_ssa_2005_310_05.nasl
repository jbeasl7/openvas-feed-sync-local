# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55802");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2005-310-05)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2005-310-05");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.375069");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'PHP' package(s) announced via the SSA:2005-310-05 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New PHP packages are available for Slackware 10.2 and -current to fix minor
security issues relating to the overwriting of the GLOBALS array.

It has been reported here that this new version of PHP also breaks
squirrelmail and probably some other things. Given the vague nature of
the security report, it's possible that the cure might be worse than the
disease as far as this upgrade is concerned. If you encounter problems,
you may wish to drop back to 4.4.0, and I believe that doing so is
relatively safe. I understand at least some of the issues are fixed in
CVS already, so perhaps another maintenance release is not far off.

Thanks to Gerardo Exequiel Pozzi for bringing the issues with 4.4.1 to my
attention so that this additional information could be included here.


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/php-4.4.1-i486-1.tgz: Upgraded to php-4.4.1.
 Fixes a number of bugs, including several minor security fixes relating to
 the overwriting of the GLOBALS array.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'PHP' package(s) on Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.1-i486-1", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.1-i486-1", rls:"SLKcurrent"))) {
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
