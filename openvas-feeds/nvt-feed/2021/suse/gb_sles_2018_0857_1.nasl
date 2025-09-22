# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0857.1");
  script_cve_id("CVE-2017-11524", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-13768", "CVE-2017-14314", "CVE-2017-14505", "CVE-2017-14739", "CVE-2017-15016", "CVE-2017-15017", "CVE-2017-16352", "CVE-2017-16353", "CVE-2017-18209", "CVE-2017-18211", "CVE-2017-9500", "CVE-2018-7443", "CVE-2018-7470", "CVE-2018-8804");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 17:43:12 +0000 (Fri, 16 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0857-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0857-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180857-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086011");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-April/003859.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0857-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes several issues.

These security issues were fixed:

- CVE-2018-8804: The WriteEPTImage function allowed remote attackers to cause a
 denial of service (double free and application crash) or possibly have
 unspecified other impact via a crafted file (bsc#1086011).
- CVE-2017-11524: The WriteBlob function allowed remote attackers to cause a
 denial of service (assertion failure and application exit) via a crafted file
 (bsc#1050087).
- CVE-2017-18209: Prevent NULL pointer dereference in the
 GetOpenCLCachedFilesDirectory function caused by a memory allocation result
 that was not checked, related to GetOpenCLCacheDirectory (bsc#1083628).
- CVE-2017-18211: Prevent NULL pointer dereference in the function
 saveBinaryCLProgram caused by a program-lookup result not being checked,
 related to CacheOpenCLKernel (bsc#1083634).
- CVE-2017-9500: Prevent assertion failure in the function
 ResetImageProfileIterator, which allowed attackers to cause a denial of service
 via a crafted file (bsc#1043290).
- CVE-2017-14739: The AcquireResampleFilterThreadSet function mishandled failed
 memory allocation, which allowed remote attackers to cause a denial of service
 (NULL Pointer Dereference in DistortImage in MagickCore/distort.c, and
 application crash) via unspecified vectors (bsc#1060382).
- CVE-2017-16353: Prevent memory information disclosure in the DescribeImage
 function caused by a heap-based buffer over-read. The portion of the code
 containing the vulnerability is responsible for printing the IPTC Profile
 information contained in the image. This vulnerability can be triggered with a
 specially crafted MIFF file. There is an out-of-bounds buffer dereference
 because certain increments were never checked (bsc#1066170).
- CVE-2017-16352: Prevent a heap-based buffer overflow in the 'Display visual
 image directory' feature of the DescribeImage() function. One possible way to
 trigger the vulnerability is to run the identify command on a specially crafted
 MIFF format file with the verbose flag (bsc#1066168).
- CVE-2017-14314: Prevent off-by-one error in the DrawImage function that
 allowed remote attackers to cause a denial of service (DrawDashPolygon
 heap-based buffer over-read and application crash) via a crafted file
 (bsc#1058630).
- CVE-2017-13768: Prevent NULL pointer dereference in the IdentifyImage
 function that allowed an attacker to perform denial of service by sending a
 crafted image file (bsc#1056434).
- CVE-2017-14505: Fixed handling of NULL arrays, which allowed attackers to
 perform Denial of Service (NULL pointer dereference and application crash in
 AcquireQuantumMemory within MagickCore/memory.c) by providing a crafted Image
 File as input (bsc#1059735).
- CVE-2018-7470: The IsWEBPImageLossless function allowed attackers to cause a
 denial of service (segmentation violation) via a crafted file (bsc#1082837).
- CVE-2018-7443: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.47.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.47.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.47.1", rls:"SLES12.0SP3"))) {
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
