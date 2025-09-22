# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0090");
  script_cve_id("CVE-2023-5520", "CVE-2024-0321", "CVE-2024-0322");
  script_tag(name:"creation_date", value:"2025-03-10 04:08:11 +0000 (Mon, 10 Mar 2025)");
  script_version("2025-03-10T05:35:40+0000");
  script_tag(name:"last_modification", value:"2025-03-10 05:35:40 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-11 20:50:46 +0000 (Thu, 11 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0090)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0090");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0090.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34071");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7320-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpac' package(s) announced via the MGASA-2025-0090 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds Read in GitHub repository gpac/gpac prior to 2.2.2.
(CVE-2023-5520)
Stack-based Buffer Overflow in GitHub repository gpac/gpac prior to
2.3-DEV. (CVE-2024-0321)
Out-of-bounds Read in GitHub repository gpac/gpac prior to 2.3-DEV.
(CVE-2024-0322)");

  script_tag(name:"affected", value:"'gpac' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gpac", rpm:"gpac~2.2.1~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpac-devel", rpm:"lib64gpac-devel~2.2.1~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gpac12", rpm:"lib64gpac12~2.2.1~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpac-devel", rpm:"libgpac-devel~2.2.1~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpac12", rpm:"libgpac12~2.2.1~1.2.mga9.tainted", rls:"MAGEIA9"))) {
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
