# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1033.1");
  script_cve_id("CVE-2018-16412", "CVE-2018-16413", "CVE-2018-16644", "CVE-2018-20467", "CVE-2019-10650", "CVE-2019-11007", "CVE-2019-11008", "CVE-2019-11009", "CVE-2019-7175", "CVE-2019-7395", "CVE-2019-7397", "CVE-2019-7398", "CVE-2019-9956");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-27 11:51:51 +0000 (Wed, 27 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1033-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1033-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191033-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132060");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-April/005366.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2019:1033-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

Security issues fixed:

- CVE-2019-9956: Fixed a stack-based buffer overflow in PopHexPixel() (bsc#1130330).
- CVE-2019-10650: Fixed a heap-based buffer over-read in WriteTIFFImage() (bsc#1131317).
- CVE-2019-7175: Fixed multiple memory leaks in DecodeImage function (bsc#1128649).
- CVE-2018-20467: Fixed infinite loop in coders/bmp.c (bsc#1120381).
- CVE-2019-7398: Fixed a memory leak in the function WriteDIBImage (bsc#1124365).
- CVE-2019-7397: Fixed a memory leak in the function WritePDFImage (bsc#1124366).
- CVE-2019-7395: Fixed a memory leak in the function WritePSDChannel (bsc#1124368).
- CVE-2018-16413: Fixed a heap-based buffer over-read in PushShortPixel() (bsc#1106989).
- CVE-2018-16412: Fixed a heap-based buffer over-read in ParseImageResourceBlocks() (bsc#1106996).
- CVE-2018-16644: Fixed a regression in dcm coder (bsc#1107609).
- CVE-2019-11007: Fixed a heap-based buffer overflow in ReadMNGImage() (bsc#1132060).
- CVE-2019-11008: Fixed a heap-based buffer overflow in WriteXWDImage() (bsc#1132054).
- CVE-2019-11009: Fixed a heap-based buffer over-read in ReadXWDImage() (bsc#1132053).

- Added extra -config- packages with Postscript/EPS/PDF readers still enabled.

 Removing the PS decoders is used to harden ImageMagick against security issues within
 ghostscript. Enabling them might impact security. (bsc#1122033)

 These are two packages that can be selected:

 - ImageMagick-config-6-SUSE: This has the PS decoders disabled.
 - ImageMagick-config-6-upstream: This has the PS decoders enabled.

 Depending on your local needs install either one of them. The default is the -SUSE configuration.");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.108.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.108.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.108.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.108.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.108.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.108.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.108.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.108.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.108.1", rls:"SLES12.0SP4"))) {
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
