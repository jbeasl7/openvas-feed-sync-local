# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.205.01");
  script_cve_id("CVE-2024-0760", "CVE-2024-1737", "CVE-2024-1975", "CVE-2024-4076");
  script_tag(name:"creation_date", value:"2024-07-24 04:09:05 +0000 (Wed, 24 Jul 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-23 15:15:05 +0000 (Tue, 23 Jul 2024)");

  script_name("Slackware: Security Advisory (SSA:2024-205-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-205-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.434746");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-0760");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-1737");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-1975");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-4076");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SSA:2024-205-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New bind packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/bind-9.18.28-i586-1_slack15.0.txz: Upgraded.
 Please note that we have moved to the 9.18 branch, as 9.16 is EOL.
 This update fixes security issues:
 Remove SIG(0) support from named as a countermeasure for CVE-2024-1975.
 qctx-zversion was not being cleared when it should have been leading to
 an assertion failure if it needed to be reused.
 An excessively large number of rrtypes per owner can slow down database query
 processing, so a limit has been placed on the number of rrtypes that can be
 stored per owner (node) in a cache or zone database. This is configured with
 the new 'max-rrtypes-per-name' option, and defaults to 100.
 Excessively large rdatasets can slow down database query processing, so a
 limit has been placed on the number of records that can be stored per
 rdataset in a cache or zone database. This is configured with the new
 'max-records-per-type' option, and defaults to 100.
 Malicious DNS client that sends many queries over TCP but never reads
 responses can cause server to respond slowly or not respond at all for other
 clients.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'bind' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.18.28-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.18.28-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.18.28-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.18.28-x86_64-1", rls:"SLKcurrent"))) {
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
