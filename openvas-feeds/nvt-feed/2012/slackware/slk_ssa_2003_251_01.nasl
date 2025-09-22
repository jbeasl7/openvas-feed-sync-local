# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53887");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-251-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-251-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.418022");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'inetd' package(s) announced via the SSA:2003-251-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upgraded inetd packages are available for Slackware 8.1, 9.0 and
- -current. These fix a previously hard-coded limit of 256
connections-per-minute, after which the given service is disabled
for ten minutes. An attacker could use a quick burst of
connections every ten minutes to effectively disable a service.

Once upon a time, this was an intentional feature of inetd, but in
today's world it has become a bug. Even having inetd look at the
source IP and try to limit only the source of the attack would be
problematic since TCP source addresses are so easily faked. So,
the approach we have taken (borrowed from FreeBSD) is to disable
this rate limiting 'feature' by default. It can be re-enabled by
providing a -R <rate> option on the command-line if desired, but
for obvious reasons we do not recommend this.

Any site running services through inetd that they would like
protected from this simple DoS attack should upgrade to the new
inetd package immediately.


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
patches/packages/inetd-1.79s-i386-2.tgz: Disable inetd's (stupid)
 connection limiting code which can actually cause a DoS rather than
 preventing it. The default connections-per-minute is now unlimited.
 -R 0 also removes limiting (this is now mentioned in the man page as
 well). Thanks to 3APA3A for reporting this issue.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'inetd' package(s) on Slackware 8.1, Slackware 9.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"inetd", ver:"1.79s-i386-2", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"inetd", ver:"1.79s-i386-2", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"inetd", ver:"1.79s-i486-2", rls:"SLKcurrent"))) {
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
