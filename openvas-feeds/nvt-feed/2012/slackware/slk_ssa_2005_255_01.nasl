# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55305");
  script_cve_id("CVE-2005-1848");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2005-255-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2005-255-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.434883");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcpcd' package(s) announced via the SSA:2005-255-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New dhcpcd packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, and -current to fix a minor security issue. The dhcpcd daemon
can be tricked into reading past the end of the DHCP buffer by a
malicious DHCP server, which causes the dhcpcd daemon to crash and
results in a denial of service. Of course, a malicious DHCP server
could simply give you an IP address that wouldn't work, too, such as
127.0.0.1, but since people have been asking about this issue, here's
a fix, and that's the extent of the impact. In other words, very
little real impact.

Even less detail about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]

Here are the details from the Slackware 10.1 ChangeLog:
+--------------------------+
patches/packages/dhcpcd-1.3.22pl4-i486-2.tgz: Patched an issue where a
 remote attacker can cause dhcpcd to crash.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'dhcpcd' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware current.");

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

if(release == "SLK10.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"dhcpcd", ver:"1.3.22pl4-i486-2", rls:"SLK10.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"dhcpcd", ver:"1.3.22pl4-i486-2", rls:"SLK10.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"dhcpcd", ver:"1.3.22pl4-i386-2", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"dhcpcd", ver:"1.3.22pl4-i386-2", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"dhcpcd", ver:"1.3.22pl4-i486-2", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"dhcpcd", ver:"1.3.22pl4-i486-2", rls:"SLKcurrent"))) {
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
