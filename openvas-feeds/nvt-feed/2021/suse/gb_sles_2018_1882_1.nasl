# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1882.1");
  script_cve_id("CVE-2017-11337", "CVE-2017-11338", "CVE-2017-11339", "CVE-2017-11340", "CVE-2017-11553", "CVE-2017-11591", "CVE-2017-11592", "CVE-2017-11683", "CVE-2017-12955", "CVE-2017-12956", "CVE-2017-12957", "CVE-2017-14859", "CVE-2017-14860", "CVE-2017-14862", "CVE-2017-14864");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-22 14:50:42 +0000 (Tue, 22 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1882-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1882-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181882-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2018:1882-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 to 0.26 fixes the following security issues:
- CVE-2017-14864: Prevent invalid memory address dereference in
 Exiv2::getULong that could have caused a segmentation fault and
 application crash, which leads to denial of service (bsc#1060995).
- CVE-2017-14862: Prevent invalid memory address dereference in
 Exiv2::DataValue::read that could have caused a segmentation fault and
 application crash, which leads to denial of service (bsc#1060996).
- CVE-2017-14859: Prevent invalid memory address dereference in
 Exiv2::StringValueBase::read that could have caused a segmentation fault
 and application crash, which leads to denial of service (bsc#1061000).
- CVE-2017-14860: Prevent heap-based buffer over-read in the
 Exiv2::Jp2Image::readMetadata function via a crafted input that could
 have lead to a denial of service attack (bsc#1061023).
- CVE-2017-11337: Prevent invalid free in the Action::TaskFactory::cleanup
 function via a crafted input that could have lead to a remote denial of
 service attack (bsc#1048883).
- CVE-2017-11338: Prevent infinite loop in the
 Exiv2::Image::printIFDStructure function via a crafted input that could
 have lead to a remote denial of service attack (bsc#1048883).
- CVE-2017-11339: Prevent heap-based buffer overflow in the
 Image::printIFDStructure function via a crafted input that could have
 lead to a remote denial of service attack (bsc#1048883).
- CVE-2017-11340: Prevent Segmentation fault in the XmpParser::terminate()
 function via a crafted input that could have lead to a remote denial of
 service attack (bsc#1048883).
- CVE-2017-12955: Prevent heap-based buffer overflow. The vulnerability
 caused an out-of-bounds write in Exiv2::Image::printIFDStructure(),
 which may lead to remote denial of service or possibly unspecified other
 impact (bsc#1054593).
- CVE-2017-12956: Preventn illegal address access in
 Exiv2::FileIo::path[abi:cxx11]() that could have lead to remote denial
 of service (bsc#1054592).
- CVE-2017-12957: Prevent heap-based buffer over-read that was triggered
 in the Exiv2::Image::io function and could have lead to remote denial of
 service (bsc#1054590).
- CVE-2017-11683: Prevent reachable assertion in the
 Internal::TiffReader::visitDirectory function that could have lead to a
 remote denial of service attack via crafted input (bsc#1051188).
- CVE-2017-11591: Prevent Floating point exception in the Exiv2::ValueType
 function that could have lead to a remote denial of service attack via
 crafted input (bsc#1050257).
- CVE-2017-11553: Prevent illegal address access in the extend_alias_table
 function via a crafted input could have lead to remote denial of service.
- CVE-2017-11592: Prevent mismatched Memory Management Routines
 vulnerability in the Exiv2::FileIo::seek function that could have lead
 to a remote denial of service attack (heap memory corruption) via
 crafted input.");

  script_tag(name:"affected", value:"'exiv2' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~6.3.1", rls:"SLES15.0"))) {
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
