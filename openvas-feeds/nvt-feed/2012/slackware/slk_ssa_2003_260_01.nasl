# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53884");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-260-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-260-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.368193");
  script_xref(name:"URL", value:"http://www.openssh.com/txt/buffer.adv");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSH' package(s) announced via the SSA:2003-260-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upgraded OpenSSH 3.7.1p1 packages are available for Slackware
8.1, 9.0 and -current. These fix additional buffer management
errors that were not corrected in the recent 3.7p1 release.
The possibility exists that these errors could allow a remote
exploit, so we recommend all sites running OpenSSH upgrade to
the new OpenSSH package immediately.


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Wed Sep 17 01:25:22 PDT 2003
patches/packages/openssh-3.7.1p1-i386-1.tgz: Upgraded to openssh-3.7.1p1.
 The OpenSSH advisory was updated ([link moved to references])
 and now says that you need at least version 3.7.1, which fixes some
 more buffer problems like those fixed by 3.7.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'OpenSSH' package(s) on Slackware 8.1, Slackware 9.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"3.7.1p1-i386-1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"3.7.1p1-i386-1", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"3.7.1p1-i486-1", rls:"SLKcurrent"))) {
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
