# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64571");
  script_cve_id("CVE-2009-0023", "CVE-2009-1191", "CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1891", "CVE-2009-1955", "CVE-2009-1956");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 14:11:43 +0000 (Fri, 02 Feb 2024)");

  script_name("Slackware: Security Advisory (SSA:2009-214-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.0|12\.1|12\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2009-214-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.566124");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the SSA:2009-214-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New httpd packages are available for Slackware 12.0, 12.1, 12.2, and -current
to fix security issues.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]


Here are the details from the Slackware 12.2 ChangeLog:
+--------------------------+
patches/packages/httpd-2.2.12-i486-1_slack12.2.tgz: Upgraded.
 This update fixes some security issues (from the CHANGES file):
 *) SECURITY: CVE-2009-1891 (cve.mitre.org)
 Fix a potential Denial-of-Service attack against mod_deflate or other
 modules, by forcing the server to consume CPU time in compressing a
 large file after a client disconnects. PR 39605.
 [Joe Orton, Ruediger Pluem]
 *) SECURITY: CVE-2009-1195 (cve.mitre.org)
 Prevent the 'Includes' Option from being enabled in an .htaccess
 file if the AllowOverride restrictions do not permit it.
 [Jonathan Peatfield <j.s.peatfield damtp.cam.ac.uk>, Joe Orton,
 Ruediger Pluem, Jeff Trawick]
 *) SECURITY: CVE-2009-1890 (cve.mitre.org)
 Fix a potential Denial-of-Service attack against mod_proxy in a
 reverse proxy configuration, where a remote attacker can force a
 proxy process to consume CPU time indefinitely. [Nick Kew, Joe Orton]
 *) SECURITY: CVE-2009-1191 (cve.mitre.org)
 mod_proxy_ajp: Avoid delivering content from a previous request which
 failed to send a request body. PR 46949 [Ruediger Pluem]
 *) SECURITY: CVE-2009-0023, CVE-2009-1955, CVE-2009-1956 (cve.mitre.org)
 The bundled copy of the APR-util library has been updated, fixing three
 different security issues which may affect particular configurations
 and third-party modules.
 These last three CVEs were addressed in Slackware previously with an
 update to new system apr and apr-util packages.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'httpd' package(s) on Slackware 12.0, Slackware 12.1, Slackware 12.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.12-i486-1_slack12.0", rls:"SLK12.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.12-i486-1_slack12.1", rls:"SLK12.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.12-i486-1_slack12.2", rls:"SLK12.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.12-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"httpd", ver:"2.2.12-x86_64-1", rls:"SLKcurrent"))) {
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
