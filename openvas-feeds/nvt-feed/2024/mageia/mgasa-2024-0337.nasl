# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0337");
  script_cve_id("CVE-2024-36474", "CVE-2024-42415");
  script_tag(name:"creation_date", value:"2024-10-28 04:12:33 +0000 (Mon, 28 Oct 2024)");
  script_version("2024-10-29T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-09 16:44:20 +0000 (Wed, 09 Oct 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0337)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0337");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0337.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33620");
  script_xref(name:"URL", value:"https://lwn.net/Articles/993121/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7062-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgsf' package(s) announced via the MGASA-2024-0337 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow vulnerability exists in the Compound Document Binary
File format parser of the GNOME Project G Structured File Library
(libgsf) version v1.14.52. A specially crafted file can result in an
integer overflow when processing the directory from the file that allows
for an out-of-bounds index to be used when reading and writing to an
array. This can lead to arbitrary code execution. An attacker can
provide a malicious file to trigger this vulnerability. (CVE-2024-36474)
An integer overflow vulnerability exists in the Compound Document Binary
File format parser of v1.14.52 of the GNOME Project G Structured File
Library (libgsf). A specially crafted file can result in an integer
overflow that allows for a heap-based buffer overflow when processing
the sector allocation table. This can lead to arbitrary code execution.
An attacker can provide a malicious file to trigger this vulnerability.
(CVE-2024-42415)");

  script_tag(name:"affected", value:"'libgsf' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64gsf-devel", rpm:"lib64gsf-devel~1.14.50~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsf-gir1", rpm:"lib64gsf-gir1~1.14.50~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gsf1_114", rpm:"lib64gsf1_114~1.14.50~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsf", rpm:"libgsf~1.14.50~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsf-devel", rpm:"libgsf-devel~1.14.50~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsf-gir1", rpm:"libgsf-gir1~1.14.50~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsf1_114", rpm:"libgsf1_114~1.14.50~1.1.mga9", rls:"MAGEIA9"))) {
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
