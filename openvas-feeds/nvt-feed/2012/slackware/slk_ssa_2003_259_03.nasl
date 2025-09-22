# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53963");
  script_cve_id("CVE-1999-0997");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2003-259-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-259-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.365971");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'WU-FTPD' package(s) announced via the SSA:2003-259-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upgraded WU-FTPD packages are available for Slackware 9.0 and
- -current. These fix a problem where an attacker could use a
specially crafted filename in conjunction with WU-FTPD's
conversion feature (mostly used to compress files, or produce tar
archives) to execute arbitrary commands on the server.

In addition, a MAIL_ADMIN which has been found to be insecure has
been disabled.

We do not recommend deploying WU-FTPD in situations where security
is required.


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Tue Sep 23 14:43:10 PDT 2003
pasture/dontuse/wu-ftpd/wu-ftpd-2.6.2-i486-3.tgz: Fixed a security problem in
 /etc/ftpconversions (CVE-1999-0997). There's also another hole in wu-ftpd
 which may be triggered if the MAIL_ADMIN feature (notifies the admin of
 anonymous uploads) is used, so MAIL_ADMIN has been disabled in this build.
 Also note that we've moved this from /pasture to /pasture/dontuse, which
 should tell you something.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'WU-FTPD' package(s) on Slackware 9.0, Slackware current.");

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

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"wu-ftpd", ver:"2.6.2-i386-3", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"wu-ftpd", ver:"2.6.2-i486-3", rls:"SLKcurrent"))) {
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
