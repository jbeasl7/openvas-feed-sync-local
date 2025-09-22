# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53965");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2005-170-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLKcurrent");

  script_xref(name:"Advisory-ID", value:"SSA:2005-170-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.394829");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-101748-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java' package(s) announced via the SSA:2005-170-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sun has released a couple of security advisories pertaining to both the
Java Runtime Environment and the Standard Edition Development Kit.
These could allow applets to read or write to local files. For more
details, Sun's advisories may be found here:

 [links moved to references]

Slackware repackage's Sun's Java(TM) binaries without changing them, so
the packages from Slackware -current should be used for all glibc based
Slackware versions.


Here are the details from the Slackware -current ChangeLog:
+--------------------------+
Sun Jun 19 21:45:07 PDT 2005
l/jre-1_5_0_03-i586-1.tgz: This already-issued package fixes some
 recently announced security issues that could allow applets to read
 or write to local files. See:
 [links moved to references]
 (* Security fix *)
extra/j2sdk-1.5.0_03/j2sdk-1_5_0_03-i586-1.tgz: Fixed the slack-desc
 to not include the release version to prevent future mishaps. :-)
 This already-issued package fixes some recently announced security
 issues that could allow applets to read or write to local files.
 See:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'java' package(s) on Slackware current.");

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

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"j2sdk", ver:"1_5_0_03-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"jre", ver:"1_5_0_03-i586-1", rls:"SLKcurrent"))) {
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
