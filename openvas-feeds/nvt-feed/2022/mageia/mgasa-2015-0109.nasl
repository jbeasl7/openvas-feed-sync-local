# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0109");
  script_cve_id("CVE-2015-0332", "CVE-2015-0333", "CVE-2015-0334", "CVE-2015-0335", "CVE-2015-0336", "CVE-2015-0337", "CVE-2015-0338", "CVE-2015-0339", "CVE-2015-0340", "CVE-2015-0341", "CVE-2015-0342");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0109)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0109");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0109.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15229");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15480");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-05.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0109 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.451 contains fixes to critical security
vulnerabilities found in earlier versions that could cause a crash and
potentially allow an attacker to take control of the affected system.

This update resolves memory corruption vulnerabilities that could lead
to code execution (CVE-2015-0332, CVE-2015-0333, CVE-2015-0335,
CVE-2015-0339).

This update resolves type confusion vulnerabilities that could lead
to code execution (CVE-2015-0334, CVE-2015-0336).

This update resolves a vulnerability that could lead to a cross-domain
policy bypass (CVE-2015-0337).

This update resolves a vulnerability that could lead to a file upload
restriction bypass (CVE-2015-0340).

This update resolves an integer overflow vulnerability that could lead
to code execution (CVE-2015-0338).

This update resolves use-after-free vulnerabilities that could lead
to code execution (CVE-2015-0341, CVE-2015-0342).

Additionally, the Flash Plugin package downloaded from Adobe is now
verified using recorded sha256sum and file size instead of using
insecure md5sum (mga#15229).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.451~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.451~1.mga4.nonfree", rls:"MAGEIA4"))) {
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
