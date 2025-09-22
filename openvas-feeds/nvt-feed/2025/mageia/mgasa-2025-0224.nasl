# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0224");
  script_cve_id("CVE-2025-54389", "CVE-2025-54409");
  script_tag(name:"creation_date", value:"2025-09-03 04:07:58 +0000 (Wed, 03 Sep 2025)");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-19 19:11:40 +0000 (Tue, 19 Aug 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0224)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0224");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0224.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34586");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/08/14/7");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/08/14/8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aide' package(s) announced via the MGASA-2025-0224 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper output neutralization (potential AIDE detection bypass).
(CVE-2025-54389)
Null pointer dereference after reading incorrectly encoded xattr
attributes from database (local DoS). (CVE-2025-54409)");

  script_tag(name:"affected", value:"'aide' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"aide", rpm:"aide~0.18.6~1.1.mga9", rls:"MAGEIA9"))) {
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
