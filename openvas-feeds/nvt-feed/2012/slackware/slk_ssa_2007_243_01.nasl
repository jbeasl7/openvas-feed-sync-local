# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59015");
  script_cve_id("CVE-2007-3922");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2007-243-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK12\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2007-243-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.486841");
  script_xref(name:"URL", value:"http://sunsolve.sun.com");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102995-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java' package(s) announced via the SSA:2007-243-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sun has released security advisories pertaining to both the Java
Runtime Environment and the Standard Edition Development Kit.

One such advisory may be found here:
 [link moved to references]

Updated versions of both the jre and jdk packages are provided
which address all known flaws in Java(TM) at this time. There
may be more advisories on [link moved to references] describing other
flaws that are patched with this update. Happy hunting!

Slackware repackages Sun's Java(TM) binaries without changing them,
so the packages from Slackware 12.0 should work on all glibc based
Slackware versions.


Here are the details from the Slackware 12.0 ChangeLog:
+--------------------------+
Fri Aug 31 13:33:54 CDT 2007
patches/packages/jre-6u2-i586-1.tgz:
 Upgraded to Java(TM) 2 Platform Standard Edition Runtime Environment
 Version 6.0 update 2.
 This update addresses code errors which could possibly be leveraged to
 compromise system security, though we know of no existing exploits.
 This update consists of the official Java(TM) binaries repackaged in
 Slackware's package format, and may be used on any version of Slackware
 that is based on glibc.
 For more information, see:
 [link moved to references]
 (* Security fix *)
 An additional change was made to the script that Slackware uses to
 set environment variables for Java(TM). Now, after the $JAVA_HOME
 variable is set, the next variable settings make use of it, rather
 than hard-coding the path to $JAVA_HOME. This does not fix a bug,
 but is certainly better scripting style. Thanks to Jason Byrne and
 Jean-Christophe Fargette for suggesting this change.
extra/jdk-6/jdk-6u2-i586-1.tgz: Upgraded to Java(TM) 2 Platform
 Standard Edition Development Kit Version 6.0 update 2.
 This update addresses code errors which could possibly be leveraged to
 compromise system security, though we know of no existing exploits.
 This update consists of the official Java(TM) binaries repackaged in
 Slackware's package format, and may be used on any version of Slackware
 that is based on glibc.
 For more information, see:
 [link moved to references]
 (* Security fix *)
 An additional change was made to the script that Slackware uses to
 set environment variables for Java(TM). Now, after the $JAVA_HOME
 variable is set, the next variable settings make use of it, rather
 than hard-coding the path to $JAVA_HOME. This does not fix a bug,
 but is certainly better scripting style. Thanks to Jason Byrne and
 Jean-Christophe Fargette for suggesting this change.
+--------------------------+");

  script_tag(name:"affected", value:"'java' package(s) on Slackware 12.0.");

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

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"jdk", ver:"6u2-i586-1", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"jre", ver:"6u2-i586-1", rls:"SLK12.0"))) {
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
