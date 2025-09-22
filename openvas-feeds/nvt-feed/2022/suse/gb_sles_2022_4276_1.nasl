# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4276.1");
  script_cve_id("CVE-2017-11591", "CVE-2018-11531", "CVE-2018-17581", "CVE-2018-20097", "CVE-2018-20098", "CVE-2018-20099", "CVE-2019-13109", "CVE-2019-13110", "CVE-2019-17402", "CVE-2021-29473", "CVE-2021-32815");
  script_tag(name:"creation_date", value:"2022-11-30 04:20:10 +0000 (Wed, 30 Nov 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-27 11:10:30 +0000 (Wed, 27 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4276-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4276-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224276-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189337");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/013143.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2022:4276-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 fixes the following issues:

- CVE-2019-13110: Fixed an integer-overflow and out-of-bounds read in CiffDirectory:readDirectory leads to denail of service (bsc#1142678).
- CVE-2019-13109: Fixed a denial of service in PngImage:readMetadata (bsc#1142677).
- CVE-2018-17581: Fixed an excessive stack consumption CiffDirectory:readDirectory() at crwimage_int.cpp (bsc#1110282).
- CVE-2017-11591: Fixed a floating point exception in Exiv2::ValueType (bsc#1050257).
- CVE-2019-17402: Fixed an improper validation of the total size to the offset and size leads to a crash in Exiv2::getULong in types.cpp (bsc#1153577).
- CVE-2021-32815: Fixed a deny-of-service due to assertion failure in crwimage_int.cpp (bsc#1189337).
- CVE-2018-20097: Fixed SEGV in Exiv2::Internal::TiffParserWorker::findPrimaryGroupsu (bsc#1119562).
- CVE-2021-29473: Fixed out-of-bounds read in Exiv2::Jp2Image:doWriteMetadata (bsc#1186231).
- CVE-2018-20098: Fixed a heap-based buffer over-read in Exiv2::Jp2Image::encodeJp2Header (bsc#1119560).
- CVE-2018-11531: Fixed a heap-based buffer overflow in getData in preview.cpp (bsc#1095070).
- CVE-2018-20099: exiv2: infinite loop in Exiv2::Jp2Image::encodeJp2Header (bsc#1119559).");

  script_tag(name:"affected", value:"'exiv2' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~150000.6.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~150000.6.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~150000.6.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.26.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.26.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.26.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.26.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.26.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~150000.6.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~150000.6.26.1", rls:"SLES15.0SP2"))) {
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
