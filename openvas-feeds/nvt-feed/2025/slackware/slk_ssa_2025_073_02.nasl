# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.073.02");
  script_cve_id("CVE-2025-1217", "CVE-2025-1219", "CVE-2025-1734", "CVE-2025-1736", "CVE-2025-1861");
  script_tag(name:"creation_date", value:"2025-03-17 15:24:03 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-07-03T05:42:53+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:53 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-02 20:17:38 +0000 (Wed, 02 Jul 2025)");

  script_name("Slackware: Security Advisory (SSA:2025-073-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-073-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.417265");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-1217");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-1219");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-1734");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-1736");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-1861");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-8.php#8.1.32");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the SSA:2025-073-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
extra/php81/php81-8.1.32-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 LibXML: libxml streams use wrong `content-type` header when requesting
 a redirected resource.
 Streams: Stream HTTP wrapper header check might omit basic auth header.
 Streams: Stream HTTP wrapper truncate redirect location to 1024 bytes.
 Streams: Streams HTTP wrapper does not fail for headers without colon.
 Streams: Header parser of http stream wrapper does not handle folded headers.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php' package(s) on Slackware 15.0, Slackware current.");

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

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"php81", ver:"8.1.32-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php81", ver:"8.1.32-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"8.3.19-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"8.3.19-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"8.4.5-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"8.4.5-x86_64-1", rls:"SLKcurrent"))) {
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
