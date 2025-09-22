# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1486.1");
  script_cve_id("CVE-2017-7607", "CVE-2017-7608", "CVE-2017-7609", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613", "CVE-2018-16062", "CVE-2018-16402", "CVE-2018-16403", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7150", "CVE-2019-7665");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-29 13:29:10 +0000 (Mon, 29 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1486-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1486-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191486-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the SUSE-SU-2019:1486-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for elfutils fixes the following issues:

Security issues fixed:
CVE-2017-7607: Fixed a heap-based buffer overflow in handle_gnu_hash
 (bsc#1033084)

CVE-2017-7608: Fixed a heap-based buffer overflow in
 ebl_object_note_type_name() (bsc#1033085)

CVE-2017-7609: Fixed a memory allocation failure in __libelf_decompress
 (bsc#1033086)

CVE-2017-7610: Fixed a heap-based buffer overflow in check_group
 (bsc#1033087)

CVE-2017-7611: Fixed a denial of service via a crafted ELF file
 (bsc#1033088)

CVE-2017-7612: Fixed a denial of service in check_sysv_hash() via a
 crafted ELF file (bsc#1033089)

CVE-2017-7613: Fixed denial of service caused by the missing validation
 of the number of sections and the number of segments in a crafted ELF
 file (bsc#1033090)

CVE-2018-16062: Fixed a heap-buffer overflow in
 /elfutils/libdw/dwarf_getaranges.c:156 (bsc#1106390)

CVE-2018-16402: Fixed a denial of service/double free on an attempt to
 decompress the same section twice (bsc#1107066)

CVE-2018-16403: Fixed a heap buffer overflow in readelf (bsc#1107067)

CVE-2018-18310: Fixed an invalid address read problem in
 dwfl_segment_report_module.c (bsc#1111973)

CVE-2018-18520: Fixed bad handling of ar files inside are files
 (bsc#1112726)

CVE-2018-18521: Fixed a denial of service vulnerabilities in the
 function arlib_add_symbols() used by eu-ranlib (bsc#1112723)

CVE-2019-7150: dwfl_segment_report_module doesn't check whether the dyn
 data read from core file is truncated (bsc#1123685)

CVE-2019-7665: NT_PLATFORM core file note should be a zero terminated
 string (bsc#1125007)");

  script_tag(name:"affected", value:"'elfutils' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-debuginfo", rpm:"elfutils-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-debugsource", rpm:"elfutils-debugsource~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-lang", rpm:"elfutils-lang~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm-devel", rpm:"libasm-devel~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1-debuginfo", rpm:"libasm1-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw-devel", rpm:"libdw-devel~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit-debuginfo", rpm:"libdw1-32bit-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-debuginfo", rpm:"libdw1-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-devel", rpm:"libebl-devel~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins", rpm:"libebl-plugins~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-32bit", rpm:"libebl-plugins-32bit~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-32bit-debuginfo", rpm:"libebl-plugins-32bit-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-debuginfo", rpm:"libebl-plugins-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf-devel", rpm:"libelf-devel~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit-debuginfo", rpm:"libelf1-32bit-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-debuginfo", rpm:"libelf1-debuginfo~0.168~4.5.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-debuginfo", rpm:"elfutils-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-debugsource", rpm:"elfutils-debugsource~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfutils-lang", rpm:"elfutils-lang~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm-devel", rpm:"libasm-devel~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1", rpm:"libasm1~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libasm1-debuginfo", rpm:"libasm1-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw-devel", rpm:"libdw-devel~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1", rpm:"libdw1~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit", rpm:"libdw1-32bit~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-32bit-debuginfo", rpm:"libdw1-32bit-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdw1-debuginfo", rpm:"libdw1-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-devel", rpm:"libebl-devel~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins", rpm:"libebl-plugins~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-32bit", rpm:"libebl-plugins-32bit~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-32bit-debuginfo", rpm:"libebl-plugins-32bit-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebl-plugins-debuginfo", rpm:"libebl-plugins-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf-devel", rpm:"libelf-devel~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1", rpm:"libelf1~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit", rpm:"libelf1-32bit~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-32bit-debuginfo", rpm:"libelf1-32bit-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelf1-debuginfo", rpm:"libelf1-debuginfo~0.168~4.5.3", rls:"SLES15.0SP1"))) {
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
