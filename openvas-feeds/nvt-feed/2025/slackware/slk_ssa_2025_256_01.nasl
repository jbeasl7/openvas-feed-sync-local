# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.256.01");
  script_cve_id("CVE-2018-1000156", "CVE-2018-20969", "CVE-2018-6951", "CVE-2018-6952", "CVE-2019-13636", "CVE-2019-13638", "CVE-2019-20633");
  script_tag(name:"creation_date", value:"2025-09-15 04:12:24 +0000 (Mon, 15 Sep 2025)");
  script_version("2025-09-15T05:39:20+0000");
  script_tag(name:"last_modification", value:"2025-09-15 05:39:20 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-05 18:44:44 +0000 (Mon, 05 Aug 2019)");

  script_name("Slackware: Security Advisory (SSA:2025-256-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK15\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2025-256-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.330566");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2018-20969");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2018-6951");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2018-6952");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2019-13636");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2019-13638");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2019-20633");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch' package(s) announced via the SSA:2025-256-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New patch packages are available for Slackware 15.0 to fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/patch-2.8-i586-1_slack15.0.txz: Upgraded.
 We patched CVE-2018-1000156 seven years ago (arguably the most severe of
 these flaws), but several more CVEs were silently fixed when patch-2.8
 was released earlier this year, so let's upgrade.
 Thanks to bigbadaboum for the heads-up.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'patch' package(s) on Slackware 15.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"patch", ver:"2.8-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"patch", ver:"2.8-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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
