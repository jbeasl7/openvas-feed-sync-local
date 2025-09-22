# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53874");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-346-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-346-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.364571");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lftp' package(s) announced via the SSA:2003-346-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"lftp is a file transfer program that connects to other hosts
using FTP, HTTP, and other protocols.

A security problem with lftp has been corrected with the release
of lftp-2.6.10. New packages are available for Slackware 8.1,
9.0, 9.1, and -current. Any sites using lftp should upgrade to
the new packages.


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Fri Dec 12 11:12:05 PST 2003
patches/packages/lftp-2.6.10-i486-1.tgz: Upgraded to lftp-2.6.10.
 According to the NEWS file, this includes 'security fixes in html
 parsing code' which could cause a compromise when using lftp to
 access an untrusted site.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'lftp' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"lftp", ver:"2.6.10-i386-1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"lftp", ver:"2.6.10-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"lftp", ver:"2.6.10-i486-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"lftp", ver:"2.6.10-i486-1", rls:"SLKcurrent"))) {
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
