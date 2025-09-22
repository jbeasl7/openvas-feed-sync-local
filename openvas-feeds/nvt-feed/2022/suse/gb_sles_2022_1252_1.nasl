# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1252.1");
  script_cve_id("CVE-2018-14423", "CVE-2018-16375", "CVE-2018-16376", "CVE-2018-20845", "CVE-2018-5727", "CVE-2018-5785", "CVE-2018-6616", "CVE-2020-15389", "CVE-2020-27823", "CVE-2020-6851", "CVE-2020-8112", "CVE-2021-29338", "CVE-2022-1122");
  script_tag(name:"creation_date", value:"2022-04-20 04:34:07 +0000 (Wed, 20 Apr 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-10 14:13:26 +0000 (Mon, 10 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1252-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1252-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221252-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197738");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-April/010745.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2' package(s) announced via the SUSE-SU-2022:1252-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openjpeg2 fixes the following issues:

- CVE-2018-5727: Fixed integer overflow vulnerability in theopj_t1_encode_cblks function (bsc#1076314).
- CVE-2018-5785: Fixed integer overflow caused by an out-of-bounds leftshift in the opj_j2k_setup_encoder function (bsc#1076967).
- CVE-2018-6616: Fixed excessive iteration in the opj_t1_encode_cblks function of openjp2/t1.c (bsc#1079845).
- CVE-2018-14423: Fixed division-by-zero vulnerabilities in the functions pi_next_pcrl, pi_next_cprl,and pi_next_rpcl in lib/openjp3d/pi.c (bsc#1102016).
- CVE-2018-16375: Fixed missing checks for header_info.height and header_info.width in the function pnmtoimage in bin/jpwl/convert.c (bsc#1106882).
- CVE-2018-16376: Fixed heap-based buffer overflow function t2_encode_packet in lib/openmj2/t2.c (bsc#1106881).
- CVE-2018-20845: Fixed division-by-zero in the functions pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in openmj2/pi.ci (bsc#1140130).
- CVE-2020-6851: Fixed heap-based buffer overflow in opj_t1_clbl_decode_processor (bsc#1160782).
- CVE-2020-8112: Fixed heap-based buffer overflow in opj_t1_clbl_decode_processor in openjp2/t1.c (bsc#1162090).
- CVE-2020-15389: Fixed use-after-free if t a mix of valid and invalid files in a directory operated on by the decompressor (bsc#1173578).
- CVE-2020-27823: Fixed heap buffer over-write in opj_tcd_dc_level_shift_encode() (bsc#1180457).
- CVE-2021-29338: Fixed integer overflow that allows remote attackers to crash the application (bsc#1184774).
- CVE-2022-1122: Fixed segmentation fault in opj2_decompress due to uninitialized pointer (bsc#1197738).");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit", rpm:"libopenjp2-7-32bit~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit-debuginfo", rpm:"libopenjp2-7-32bit-debuginfo~2.3.0~150000.3.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.5.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.5.1", rls:"SLES15.0SP2"))) {
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
