# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0034");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-02-12 04:12:31 +0000 (Mon, 12 Feb 2024)");
  script_version("2024-02-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-02-12 05:05:32 +0000 (Mon, 12 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0034");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0034.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32748");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6589-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'filezilla, libfilezilla' package(s) announced via the MGASA-2024-0034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fabian Baeumer, Marcus Brinkmann and Joerg Schwenk discovered that the
SSH protocol used in FileZilla is prone to a prefix truncation attack,
known as the 'Terrapin attack'. A remote attacker could use this issue
to downgrade or disable some security features and obtain sensitive
information.
This update fixes the issue.");

  script_tag(name:"affected", value:"'filezilla, libfilezilla' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.66.4~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla-devel", rpm:"lib64filezilla-devel~0.45.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla41", rpm:"lib64filezilla41~0.45.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla", rpm:"libfilezilla~0.45.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla-devel", rpm:"libfilezilla-devel~0.45.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla-i18n", rpm:"libfilezilla-i18n~0.45.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla41", rpm:"libfilezilla41~0.45.0~1.mga9", rls:"MAGEIA9"))) {
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
