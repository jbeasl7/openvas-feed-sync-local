# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0119");
  script_cve_id("CVE-2024-25260", "CVE-2025-1372", "CVE-2025-1377");
  script_tag(name:"creation_date", value:"2025-04-01 04:08:15 +0000 (Tue, 01 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-17 03:15:09 +0000 (Mon, 17 Feb 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0119)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0119");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0119.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34134");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7369-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the MGASA-2025-0119 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"elfutils v0.189 was discovered to contain a NULL pointer dereference via
the handle_verdef() function at readelf.c. (CVE-2024-25260)
GNU elfutils eu-readelf readelf.c print_string_section buffer overflow.
(CVE-2025-1372)
GNU elfutils eu-strip strip.c gelf_getsymshndx denial of service.
(CVE-2025-1377)");

  script_tag(name:"affected", value:"'elfutils' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.189~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils-devel", rpm:"lib64elfutils-devel~0.189~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils-static-devel", rpm:"lib64elfutils-static-devel~0.189~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils1", rpm:"lib64elfutils1~0.189~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils-devel", rpm:"libelfutils-devel~0.189~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils-static-devel", rpm:"libelfutils-static-devel~0.189~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils1", rpm:"libelfutils1~0.189~1.1.mga9", rls:"MAGEIA9"))) {
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
