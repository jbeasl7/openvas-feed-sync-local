# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1733.1");
  script_cve_id("CVE-2016-10254", "CVE-2016-10255", "CVE-2017-7607", "CVE-2017-7608", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613", "CVE-2018-16062", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7150", "CVE-2019-7665");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-12 21:04:36 +0000 (Tue, 12 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1733-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1733-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191733-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125007");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005656.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the SUSE-SU-2019:1733-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for elfutils fixes the following issues:

Security issues fixed:

- CVE-2018-16403: Fixed a heap-based buffer over-read that could have led to Denial of Service (bsc#1107067).
- CVE-2016-10254: Fixed a memory allocation failure in alloxate_elf (bsc#1030472).
- CVE-2019-7665: NT_PLATFORM core file note should be a zero terminated string (bsc#1125007).
- CVE-2016-10255: Fixed a memory allocation failure in libelf_set_rawdata_wrlock (bsc#1030476).
- CVE-2019-7150: Added a missing check in dwfl_segment_report_module which could have allowed truncated files
 to be read (bsc#1123685).
- CVE-2018-16062: Fixed a heap-buffer-overflow (bsc#1106390).
- CVE-2017-7611: Fixed a heap-based buffer over-read that could have led to Denial of Service (bsc#1033088).
- CVE-2017-7613: Fixed denial of service caused by the missing validation of the number of sections
 and the number of segments in a crafted ELF file (bsc#1033090).
- CVE-2017-7607: Fixed a heap-based buffer overflow in handle_gnu_hash (bsc#1033084).
- CVE-2017-7608: Fixed a heap-based buffer overflow in ebl_object_note_type_name() (bsc#1033085).
- CVE-2017-7610: Fixed a heap-based buffer overflow in check_group (bsc#1033087).
- CVE-2018-18521: Fixed multiple divide-by-zero vulnerabilities in function arlib_add_symbols() (bsc#1112723).
- CVE-2017-7612: Fixed a denial of service in check_sysv_hash() via a crafted ELF file (bsc#1033089).
- CVE-2018-18310: Fixed an invalid address read in dwfl_segment_report_module.c (bsc#1111973).
- CVE-2018-18520: Fixed bad handling of ar files inside are files (bsc#1112726).");

  script_tag(name:"affected", value:"'elfutils' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1-32bit", rpm:"libasm1-32bit~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl1", rpm:"libebl1~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl1-32bit", rpm:"libebl1-32bit~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.158~7.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1-32bit", rpm:"libasm1-32bit~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl1", rpm:"libebl1~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl1-32bit", rpm:"libebl1-32bit~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf-devel", rpm:"libelf-devel~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.158~7.7.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.158~7.7.2", rls:"SLES12.0SP4"))) {
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
