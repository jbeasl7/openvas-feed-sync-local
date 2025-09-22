# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0152");
  script_cve_id("CVE-2021-45341", "CVE-2021-45342");
  script_tag(name:"creation_date", value:"2022-04-25 04:24:37 +0000 (Mon, 25 Apr 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 14:54:25 +0000 (Mon, 31 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0152)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0152");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0152.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29996");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/MBLTKH2Q6OBOLSNHIKPW74SFFSC5A2BB/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2908");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5077");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librecad' package(s) announced via the MGASA-2022-0152 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability in CDataMoji of the jwwlib component of
LibreCAD 2.2.0-rc3 and older allows an attacker to achieve Remote Code
Execution using a crafted JWW document. (CVE-2021-45341)

A buffer overflow vulnerability in CDataList of the jwwlib component of
LibreCAD 2.2.0-rc3 and older allows an attacker to achieve Remote Code
Execution using a crafted JWW document. (CVE-2021-45342)");

  script_tag(name:"affected", value:"'librecad' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"librecad", rpm:"librecad~2.2.0~0.rc3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad-data", rpm:"librecad-data~2.2.0~0.rc3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad-doc", rpm:"librecad-doc~2.2.0~0.rc3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad-parts", rpm:"librecad-parts~2.2.0~0.rc3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librecad-plugins", rpm:"librecad-plugins~2.2.0~0.rc3.1.mga8", rls:"MAGEIA8"))) {
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
