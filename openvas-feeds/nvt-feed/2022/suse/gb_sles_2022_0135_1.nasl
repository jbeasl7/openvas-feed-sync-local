# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0135.1");
  script_cve_id("CVE-2011-5325", "CVE-2015-9261", "CVE-2016-2147", "CVE-2016-2148", "CVE-2016-6301", "CVE-2017-15873", "CVE-2017-15874", "CVE-2017-16544", "CVE-2018-1000500", "CVE-2018-1000517", "CVE-2018-20679", "CVE-2019-5747", "CVE-2021-28831", "CVE-2021-42373", "CVE-2021-42374", "CVE-2021-42375", "CVE-2021-42376", "CVE-2021-42377", "CVE-2021-42378", "CVE-2021-42379", "CVE-2021-42380", "CVE-2021-42381", "CVE-2021-42382", "CVE-2021-42383", "CVE-2021-42384", "CVE-2021-42385", "CVE-2021-42386");
  script_tag(name:"creation_date", value:"2022-01-21 03:23:01 +0000 (Fri, 21 Jan 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 19:41:56 +0000 (Wed, 17 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0135-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0135-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220135-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991940");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-January/010031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the SUSE-SU-2022:0135-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

- CVE-2011-5325: Fixed tar directory traversal (bsc#951562).
- CVE-2015-9261: Fixed segfalts and application crashes in huft_build (bsc#1102912).
- CVE-2016-2147: Fixed out of bounds write (heap) due to integer underflow in udhcpc (bsc#970663).
- CVE-2016-2148: Fixed heap-based buffer overflow in OPTION_6RD parsing (bsc#970662).
- CVE-2016-6301: Fixed NTP server denial of service flaw (bsc#991940).
- CVE-2017-15873: Fixed integer overflow in get_next_block function in archival/libarchive/decompress_bunzip2.c (bsc#1064976).
- CVE-2017-15874: Fixed integer underflow in archival/libarchive/decompress_unlzma.c (bsc#1064978).
- CVE-2017-16544: Fixed Insufficient sanitization of filenames when autocompleting (bsc#1069412).
- CVE-2018-1000500 : Fixed missing SSL certificate validation in wget (bsc#1099263).
- CVE-2018-1000517: Fixed heap-based buffer overflow in the retrieve_file_data() (bsc#1099260).
- CVE-2018-20679: Fixed out of bounds read in udhcp (bsc#1121426).
- CVE-2019-5747: Fixed out of bounds read in udhcp components (bsc#1121428).
- CVE-2021-28831: Fixed invalid free or segmentation fault via malformed gzip data (bsc#1184522).
- CVE-2021-42373: Fixed NULL pointer dereference in man leading to DoS when a section name is supplied but no page argument is given (bsc#1192869).
- CVE-2021-42374: Fixed out-of-bounds heap read in unlzma leading to information leak and DoS when crafted LZMA-compressed input is decompressed (bsc#1192869).
- CVE-2021-42375: Fixed incorrect handling of a special element in ash leading to DoS when processing a crafted shell command, due to the shell mistaking specific characters for reserved characters (bsc#1192869).
- CVE-2021-42376: Fixed NULL pointer dereference in hush leading to DoS when processing a crafted shell command (bsc#1192869).
- CVE-2021-42377: Fixed attacker-controlled pointer free in hush leading to DoS and possible code execution when processing a crafted shell command (bsc#1192869).
- CVE-2021-42378: Fixed use-after-free in awk leading to DoS and possibly code execution when processing a crafted awk pattern in the getvar_i function (bsc#1192869).
- CVE-2021-42379: Fixed use-after-free in awk leading to DoS and possibly code execution when processing a crafted awk pattern in the next_input_file function (bsc#1192869).
- CVE-2021-42380: Fixed use-after-free in awk leading to DoS and possibly code execution when processing a crafted awk pattern in the clrvar function (bsc#1192869).
- CVE-2021-42381: Fixed use-after-free in awk leading to DoS and possibly code execution when processing a crafted awk pattern in the hash_init function (bsc#1192869).
- CVE-2021-42382: Fixed use-after-free in awk leading to DoS and possibly code execution when processing a crafted awk pattern in the getvar_s function (bsc#1192869).
- CVE-2021-42383: Fixed use-after-free in awk leading to DoS and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'busybox' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.34.1~4.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.34.1~4.9.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.34.1~4.9.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.34.1~4.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.34.1~4.9.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.34.1~4.9.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.34.1~4.9.1", rls:"SLES15.0SP2"))) {
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
