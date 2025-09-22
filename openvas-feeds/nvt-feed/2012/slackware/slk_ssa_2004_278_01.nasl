# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53907");
  script_cve_id("CVE-2004-0880", "CVE-2004-0881");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Slackware: Security Advisory (SSA:2004-278-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-278-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.417584");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'getmail' package(s) announced via the SSA:2004-278-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New getmail packages are available for Slackware 9.1, 10.0 and -current to
fix a security issue. If getmail is used as root to deliver to user owned
files or directories, it can be made to overwrite system files.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]

Here are the details from the Slackware 10.0 ChangeLog:
+--------------------------+
patches/packages/getmail-4.2.0-noarch-1.tgz: Upgraded to
 getmaii-4.2.0. Earlier versions contained a local security flaw
 when used in an insecure fashion (surprise, running something as
 root that writes to user-controlled files or directories could
 allow the old symlink attack to clobber system files! :-)
 From the getmail CHANGELOG:
 This vulnerability is not exploitable if the administrator does
 not deliver mail to the maildirs/mbox files of untrusted local
 users, or if getmail is configured to use an external
 unprivileged MDA. This vulnerability is not remotely exploitable.
 Most users would not use getmail in such as way as to be vulnerable
 to this flaw, but if your site does this package closes the hole.
 I'd also recommend not using getmail like this. Either run it as the
 user that owns the target mailbox, or deliver through an external MDA.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'getmail' package(s) on Slackware 9.1, Slackware 10.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"getmail", ver:"4.2.0-noarch-1", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"getmail", ver:"3.2.5-noarch-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"getmail", ver:"4.2.0-noarch-1", rls:"SLKcurrent"))) {
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
