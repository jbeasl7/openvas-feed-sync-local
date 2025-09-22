# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0200");
  script_cve_id("CVE-2025-5914", "CVE-2025-5915", "CVE-2025-5916", "CVE-2025-5917");
  script_tag(name:"creation_date", value:"2025-07-03 04:16:16 +0000 (Thu, 03 Jul 2025)");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 11:15:27 +0000 (Tue, 12 Aug 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0200)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0200");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0200.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34402");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7601-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the MGASA-2025-0200 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Double free at archive_read_format_rar_seek_data() in
archive_read_support_format_rar.c. (CVE-2025-5914)
Heap buffer over read in copy_from_lzss_window() at
archive_read_support_format_rar.c. (CVE-2025-5915)
Integer overflow while reading warc files at
archive_read_support_format_warc.c. (CVE-2025-5916)
Off by one error in build_ustar_entry_name() at
archive_write_set_format_pax.c. (CVE-2025-5917)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"bsdcat", rpm:"bsdcat~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdcpio", rpm:"bsdcpio~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive-devel", rpm:"lib64archive-devel~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive13", rpm:"lib64archive13~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.6.2~5.5.mga9", rls:"MAGEIA9"))) {
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
