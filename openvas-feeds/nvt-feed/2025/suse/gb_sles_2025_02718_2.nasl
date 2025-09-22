# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02718.2");
  script_cve_id("CVE-2025-5914", "CVE-2025-5915", "CVE-2025-5916", "CVE-2025-5917", "CVE-2025-5918");
  script_tag(name:"creation_date", value:"2025-08-22 04:11:56 +0000 (Fri, 22 Aug 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-12 11:15:27 +0000 (Tue, 12 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02718-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02718-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502718-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244336");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041311.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the SUSE-SU-2025:02718-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libarchive fixes the following issues:

- CVE-2025-5914: Fixed double free due to an integer overflow in the archive_read_format_rar_seek_data() function (bsc#1244272)
- CVE-2025-5915: Fixed heap buffer over read in copy_from_lzss_window() at archive_read_support_format_rar.c (bsc#1244273)
- CVE-2025-5916: Fixed integer overflow while reading warc files at archive_read_support_format_warc.c (bsc#1244270)
- CVE-2025-5917: Fixed off by one error in build_ustar_entry_name() at archive_write_set_format_pax.c (bsc#1244336)
- CVE-2025-5918: Fixed reading past EOF may be triggered for piped file streams (bsc#1244279)");

  script_tag(name:"affected", value:"'libarchive' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.5.1~150400.3.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.5.1~150400.3.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.5.1~150400.3.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.5.1~150400.3.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.5.1~150400.3.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.5.1~150400.3.21.1", rls:"SLES15.0SP5"))) {
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
