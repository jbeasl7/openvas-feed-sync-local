# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1553.2");
  script_cve_id("CVE-2016-6328", "CVE-2017-7544", "CVE-2018-20030", "CVE-2019-9278", "CVE-2020-0093", "CVE-2020-12767", "CVE-2020-13112", "CVE-2020-13113", "CVE-2020-13114");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-21 19:44:10 +0000 (Thu, 21 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1553-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1553-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201553-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libexif' package(s) announced via the SUSE-SU-2020:1553-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libexif to 0.6.22 fixes the following issues:

Security issues fixed:

CVE-2016-6328: Fixed an integer overflow in parsing MNOTE entry data of
 the input file (bsc#1055857).

CVE-2017-7544: Fixed an out-of-bounds heap read vulnerability in
 exif_data_save_data_entry function in libexif/exif-data.c (bsc#1059893).

CVE-2018-20030: Fixed a denial of service by endless recursion
 (bsc#1120943).

CVE-2019-9278: Fixed an integer overflow (bsc#1160770).

CVE-2020-0093: Fixed an out-of-bounds read in exif_data_save_data_entry
 (bsc#1171847).

CVE-2020-12767: Fixed a divide-by-zero error in exif_entry_get_value
 (bsc#1171475).

CVE-2020-13112: Fixed a time consumption DoS when parsing canon array
 markers (bsc#1172121).

CVE-2020-13113: Fixed a potential use of uninitialized memory
 (bsc#1172105).

CVE-2020-13114: Fixed various buffer overread fixes due to integer
 overflows in maker notes (bsc#1172116).

Non-security issues fixed:

libexif was updated to version 0.6.22:
 * New translations: ms
 * Updated translations for most languages
 * Some useful EXIF 2.3 tag added:
 * EXIF_TAG_GAMMA
 * EXIF_TAG_COMPOSITE_IMAGE
 * EXIF_TAG_SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE
 * EXIF_TAG_SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE
 * EXIF_TAG_GPS_H_POSITIONING_ERROR
 * EXIF_TAG_CAMERA_OWNER_NAME
 * EXIF_TAG_BODY_SERIAL_NUMBER
 * EXIF_TAG_LENS_SPECIFICATION
 * EXIF_TAG_LENS_MAKE
 * EXIF_TAG_LENS_MODEL
 * EXIF_TAG_LENS_SERIAL_NUMBER");

  script_tag(name:"affected", value:"'libexif' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libexif-debugsource", rpm:"libexif-debugsource~0.6.22~5.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexif-devel", rpm:"libexif-devel~0.6.22~5.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexif12", rpm:"libexif12~0.6.22~5.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexif12-debuginfo", rpm:"libexif12-debuginfo~0.6.22~5.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexif12-32bit", rpm:"libexif12-32bit~0.6.22~5.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexif12-32bit-debuginfo", rpm:"libexif12-32bit-debuginfo~0.6.22~5.6.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libexif-debugsource", rpm:"libexif-debugsource~0.6.22~5.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexif12-32bit", rpm:"libexif12-32bit~0.6.22~5.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexif12-32bit-debuginfo", rpm:"libexif12-32bit-debuginfo~0.6.22~5.6.1", rls:"SLES15.0SP1"))) {
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
