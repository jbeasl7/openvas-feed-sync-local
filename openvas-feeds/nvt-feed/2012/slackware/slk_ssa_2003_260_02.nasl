# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53883");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-260-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-260-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.452857");
  script_xref(name:"URL", value:"http://www.sendmail.org/8.12.10.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Sendmail' package(s) announced via the SSA:2003-260-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The sendmail packages in Slackware 8.1, 9.0, and -current have been
patched to fix security problems. These issues seem to be remotely
exploitable, so all sites running sendmail should upgrade right away.

Sendmail's 8.12.10 announcement may be found here:
 [link moved to references]

Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Wed Sep 17 10:10:26 PDT 2003
patches/packages/sendmail-8.12.10-i386-1.tgz: Upgraded to sendmail-8.12.10.
 This fixes security issues as noted in Sendmail's RELEASE_NOTES:

 'SECURITY: Fix a buffer overflow in address parsing. Problem
 detected by Michal Zalewski, patch from Todd C. Miller
 of Courtesan Consulting.
 Fix a potential buffer overflow in ruleset parsing. This problem
 is not exploitable in the default sendmail configuration,
 only if non-standard rulesets recipient (2), final (4), or
 mailer-specific envelope recipients rulesets are used then a
 problem may occur. Problem noted by Timo Sirainen.'

 We recommend that sites running Sendmail upgrade immediately.

 (* Security fix *)
patches/packages/sendmail-cf-8.12.10-noarch-1.tgz: Upgraded to config files
 for sendmail-8.12.10.
+--------------------------+");

  script_tag(name:"affected", value:"'Sendmail' package(s) on Slackware 8.1, Slackware 9.0, Slackware current.");

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

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.12.10-i386-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.12.10-noarch-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.12.10-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.12.10-noarch-1", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.12.10-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.12.10-noarch-1", rls:"SLKcurrent"))) {
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
