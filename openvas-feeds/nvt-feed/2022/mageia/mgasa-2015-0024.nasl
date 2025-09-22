# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0024");
  script_cve_id("CVE-2015-0301", "CVE-2015-0302", "CVE-2015-0303", "CVE-2015-0304", "CVE-2015-0305", "CVE-2015-0306", "CVE-2015-0307", "CVE-2015-0308", "CVE-2015-0309");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0024");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0024.html");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-01.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15035");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.429 contains fixes to critical security
vulnerabilities found in earlier versions that could potentially allow an
attacker to take control of the affected system.

This update resolves an improper file validation issue (CVE-2015-0301).

This update resolves an information disclosure vulnerability that could be
exploited to capture keystrokes on the affected system (CVE-2015-0302).

This update resolves memory corruption vulnerabilities that could lead to
code execution (CVE-2015-0303, CVE-2015-0306).

This update resolves heap-based buffer overflow vulnerabilities that could
lead to code execution (CVE-2015-0304, CVE-2015-0309).

This update resolves a type confusion vulnerability that could lead to code
execution (CVE-2015-0305).

This update resolves an out-of-bounds read vulnerability that could be
exploited to leak memory addresses (CVE-2015-0307).

This update resolves a use-after-free vulnerability that could lead to code
execution (CVE-2015-0308).");

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

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.429~1.mga4.nonfree", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.429~1.mga4.nonfree", rls:"MAGEIA4"))) {
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
