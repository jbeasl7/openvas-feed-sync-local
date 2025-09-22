# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53939");
  script_cve_id("CVE-2004-0233");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Slackware: Security Advisory (SSA:2004-110-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-110-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.404389");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'utempter' package(s) announced via the SSA:2004-110-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New utempter packages are available for Slackware 9.1 and -current to
fix a security issue. (Slackware 9.1 was the first version of Slackware
to use the libutempter library, and earlier versions of Slackware are
not affected by this issue)

The utempter package provides a utility and shared library that
allows terminal applications such as xterm and screen to update
/var/run/utmp and /var/log/wtmp without requiring root privileges.
Steve Grubb has identified an issue with utempter-0.5.2 where
under certain circumstances an attacker could cause it to
overwrite files through a symlink. This has been addressed by
upgrading the utempter package to use Dmitry V. Levin's new
implementation of libutempter that does not have this bug.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]

Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Mon Apr 19 13:51:01 PDT 2004
patches/packages/utempter-1.1.1-i486-1.tgz: Upgraded to libutempter-1.1.1
 (this is a new version written by Dmitry V. Levin of ALT Linux).
 This upgrade fixes a low-level security issue in utempter-0.5.2 where
 utempter could possibly be tricked into writing through a symlink, and is
 a cleaner implementation all-around.
 For more details, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'utempter' package(s) on Slackware 9.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"utempter", ver:"1.1.1-i486-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"utempter", ver:"1.1.1-i486-1", rls:"SLKcurrent"))) {
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
