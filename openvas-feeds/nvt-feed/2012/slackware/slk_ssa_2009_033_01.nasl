# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63337");
  script_cve_id("CVE-2008-0386", "CVE-2009-0068");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2009-033-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2009-033-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.492359");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xdg-utils' package(s) announced via the SSA:2009-033-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New xdg-utils packages are available for Slackware 12.2 and -current to
fix security issues. Applications that use /etc/mailcap could be tricked
into running an arbitrary script through xdg-open, and a separate flaw in
xdg-open could allow the execution of arbitrary commands embedded in untrusted
input provided to xdg-open.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]


Here are the details from the Slackware 12.2 ChangeLog:
+--------------------------+
patches/packages/xdg-utils-1.0.2-noarch-3_slack12.2.tgz:
 This update fixes two security issues. First, use of xdg-open in
 /etc/mailcap was found to be unsafe -- xdg-open passes along downloaded files
 without indicating what mime type they initially presented themselves as,
 leaving programs further down the processing chain to discover the file type
 again. This makes it rather trivial to present a script (such as a .desktop
 file) as a document type (like a PDF) so that it looks safe to click on in a
 browser, but will result in the execution of an arbitrary script. It might
 be safe to send files to trusted applications in /etc/mailcap, but it does
 not seem to be safe to send files to xdg-open in /etc/mailcap.
 This package will comment out calls to xdg-open in /etc/mailcap if they are
 determined to have been added by a previous version of this package.
 If you've made any local customizations to /etc/mailcap, be sure to check
 that there are no uncommented calls to xdg-open after installing this update.
 Thanks to Manuel Reimer for discovering this issue.
 For more information, see:
 [link moved to references]
 Another bug in xdg-open fails to sanitize input properly allowing the
 execution of arbitrary commands. This was fixed in the xdg-utils repository
 quite some time ago (prior to the inclusion of xdg-utils in Slackware), but
 was never fixed in the official release of xdg-utils. The sources for
 xdg-utils in Slackware have now been updated from the repo to fix the problem.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'xdg-utils' package(s) on Slackware 12.2, Slackware current.");

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

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"xdg-utils", ver:"1.0.2-noarch-3_slack12.2", rls:"SLK12.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"xdg-utils", ver:"1.0.2-noarch-3", rls:"SLKcurrent"))) {
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
