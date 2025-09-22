# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61470");
  script_cve_id("CVE-2008-0891", "CVE-2008-1672");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2008-210-08)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(11\.0|12\.0|12\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2008-210-08");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.562004");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SSA:2008-210-08 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssl packages are available for Slackware 11.0, 12.0, 12.1, and -current
to fix security issues.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]

Upgraded OpenSSH packages have been provided to make sure that ssh is not
broken my the update -- especially if your machine is a remote one, be SURE
to upgrade to the new openssh package as well!


Here are the details from the Slackware 12.1 ChangeLog:
+--------------------------+
patches/packages/openssl-0.9.8h-i486-1_slack12.1.tgz:
 Upgraded to OpenSSL 0.9.8h.
 The Codenomicon TLS test suite uncovered security bugs in OpenSSL.
 If OpenSSL was compiled using non-default options (Slackware's package
 is not), then a malicious packet could cause a crash. Also, a malformed
 TLS handshake could also lead to a crash.
 For more information, see:
 [links moved to references]
 When upgrading OpenSSL, it is VERY IMPORTANT to also upgrade OpenSSH, or
 it is possible to be unable to log back into sshd!
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'openssl' package(s) on Slackware 11.0, Slackware 12.0, Slackware 12.1, Slackware current.");

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

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"5.1p1-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8h-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8h-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"5.1p1-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8h-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8h-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"5.1p1-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8h-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8h-i486-1_slack12.1", rls:"SLK12.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"openssh", ver:"5.1p1-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8h-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8h-i486-1", rls:"SLKcurrent"))) {
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
