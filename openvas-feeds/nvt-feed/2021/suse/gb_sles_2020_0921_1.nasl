# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0921.1");
  script_cve_id("CVE-2017-1000126", "CVE-2017-9239", "CVE-2018-12264", "CVE-2018-12265", "CVE-2018-17229", "CVE-2018-17230", "CVE-2018-17282", "CVE-2018-19108", "CVE-2018-19607", "CVE-2018-9305", "CVE-2019-13114");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 13:39:03 +0000 (Thu, 02 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0921-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0921-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200921-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the SUSE-SU-2020:0921-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 fixes the following issues:

exiv2 was updated to latest 0.26 branch, fixing bugs and security issues:

CVE-2017-1000126: Fixed an out of bounds read in webp parser
 (bsc#1068873).

CVE-2017-9239: Fixed a segmentation fault in
 TiffImageEntry::doWriteImage function (bsc#1040973).

CVE-2018-12264: Fixed an integer overflow in LoaderTiff::getData() which
 might have led to an out-of-bounds read (bsc#1097600).

CVE-2018-12265: Fixed integer overflows in LoaderExifJpeg which could
 have led to memory corruption (bsc#1097599).

CVE-2018-17229: Fixed a heap based buffer overflow in Exiv2::d2Data via
 a crafted image (bsc#1109175).

CVE-2018-17230: Fixed a heap based buffer overflow in Exiv2::d2Data via
 a crafted image (bsc#1109176).

CVE-2018-17282: Fixed a null pointer dereference in
 Exiv2::DataValue::copy (bsc#1109299).

CVE-2018-19108: Fixed an integer overflow in
 Exiv2::PsdImage::readMetadata which could have led to infinite loop
 (bsc#1115364).

CVE-2018-19607: Fixed a null pointer dereference in Exiv2::isoSpeed
 which might have led to denial
 of service (bsc#1117513).

CVE-2018-9305: Fixed an out of bounds read in IptcData::printStructure
 which might have led to information leak or denial of service
 (bsc#1088424).

CVE-2019-13114: Fixed a null pointer dereference which might have led to
 denial of service via a crafted response of an malicious http server
 (bsc#1142684).");

  script_tag(name:"affected", value:"'exiv2' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~6.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~6.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~6.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~6.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~6.8.1", rls:"SLES15.0SP1"))) {
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
