# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56966");
  script_cve_id("CVE-2006-1173");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2006-166-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-166-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.631382");
  script_xref(name:"URL", value:"http://www.sendmail.com/security/advisories/SA-200605-01.txt.asc");
  script_xref(name:"URL", value:"http://www.sendmail.com/security/advisories/SA-200605-01/faq.shtml");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sendmail' package(s) announced via the SSA:2006-166-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New sendmail packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, 10.2, and -current to fix a possible denial-of-service issue.

Sendmail's complete advisory may be found here:
 [link moved to references]

Sendmail has also provided an FAQ about this issue:
 [link moved to references]

The CVE entry for this issue may be found here:
 [link moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/sendmail-8.13.7-i486-1_slack10.2.tgz:
 Upgraded to sendmail-8.13.7.
 Fixes a potential denial of service problem caused by excessive recursion
 leading to stack exhaustion when attempting delivery of a malformed MIME
 message. This crashes sendmail's queue processing daemon, which in turn
 can lead to two problems: depending on the settings, these crashed
 processes may create coredumps which could fill a drive partition, and
 such a malformed message in the queue will cause queue processing to
 cease when the message is reached, causing messages that are later in
 the queue to not be processed.
 Sendmail's complete advisory may be found here:
 [link moved to references]
 Sendmail has also provided an FAQ about this issue:
 [link moved to references]
 The CVE entry for this issue may be found here:
 [link moved to references]
 (* Security fix *)
patches/packages/sendmail-cf-8.13.7-noarch-1_slack10.2.tgz:
 Upgraded to sendmail-8.13.7 configs.
+--------------------------+");

  script_tag(name:"affected", value:"'sendmail' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.13.7-i486-1_slack10.0", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.13.7-noarch-1_slack10.0", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.13.7-i486-1_slack10.1", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.13.7-noarch-1_slack10.1", rls:"SLK10.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.13.7-i486-1_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.13.7-noarch-1_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.13.7-i386-1_slack8.1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.13.7-noarch-1_slack8.1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.13.7-i386-1_slack9.0", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.13.7-noarch-1_slack9.0", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.13.7-i486-1_slack9.1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.13.7-noarch-1_slack9.1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail", ver:"8.13.7-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"sendmail-cf", ver:"8.13.7-noarch-1", rls:"SLKcurrent"))) {
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
