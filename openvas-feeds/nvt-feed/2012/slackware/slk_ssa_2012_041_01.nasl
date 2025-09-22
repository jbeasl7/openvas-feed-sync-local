# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71965");
  script_cve_id("CVE-2011-3368", "CVE-2011-3607", "CVE-2011-4317", "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053");
  script_tag(name:"creation_date", value:"2012-09-10 11:16:18 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2012-041-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.0|12\.1|12\.2|13\.0|13\.1|13\.37|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2012-041-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2012&m=slackware-security.792124");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the SSA:2012-041-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New httpd packages are available for Slackware 12.0, 12.1, 12.2, 13.0, 13.1,
13.37, and -current to fix security issues. The apr-util package has also been
updated to the latest version.


Here are the details from the Slackware 13.37 ChangeLog:
+--------------------------+
patches/packages/apr-util-1.4.1-i486-1_slack13.37.txz: Upgraded.
 Version bump for httpd upgrade.
patches/packages/httpd-2.2.22-i486-1_slack13.37.txz: Upgraded.
 *) SECURITY: CVE-2011-3368 (cve.mitre.org)
 Reject requests where the request-URI does not match the HTTP
 specification, preventing unexpected expansion of target URLs in
 some reverse proxy configurations. [Joe Orton]
 *) SECURITY: CVE-2011-3607 (cve.mitre.org)
 Fix integer overflow in ap_pregsub() which, when the mod_setenvif module
 is enabled, could allow local users to gain privileges via a .htaccess
 file. [Stefan Fritsch, Greg Ames]
 *) SECURITY: CVE-2011-4317 (cve.mitre.org)
 Resolve additional cases of URL rewriting with ProxyPassMatch or
 RewriteRule, where particular request-URIs could result in undesired
 backend network exposure in some configurations.
 [Joe Orton]
 *) SECURITY: CVE-2012-0021 (cve.mitre.org)
 mod_log_config: Fix segfault (crash) when the '%{cookiename}C' log format
 string is in use and a client sends a nameless, valueless cookie, causing
 a denial of service. The issue existed since version 2.2.17. PR 52256.
 [Rainer Canavan <rainer-apache 7val com>]
 *) SECURITY: CVE-2012-0031 (cve.mitre.org)
 Fix scoreboard issue which could allow an unprivileged child process
 could cause the parent to crash at shutdown rather than terminate
 cleanly. [Joe Orton]
 *) SECURITY: CVE-2012-0053 (cve.mitre.org)
 Fix an issue in error responses that could expose 'httpOnly' cookies
 when no custom ErrorDocument is specified for status code 400.
 [Eric Covener]
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'httpd' package(s) on Slackware 12.0, Slackware 12.1, Slackware 12.2, Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-i486-1_slack12.0", rls:"SLK12.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-i486-1_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-i486-1_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-x86_64-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-x86_64-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-x86_64-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-x86_64-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.37") {

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-i486-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-x86_64-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-i486-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-x86_64-1_slack13.37", rls:"SLK13.37"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"apr-util", ver:"1.4.1-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.22-x86_64-1", rls:"SLKcurrent"))) {
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
