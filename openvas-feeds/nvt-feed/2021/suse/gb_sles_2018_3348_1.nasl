# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3348.1");
  script_cve_id("CVE-2017-17934", "CVE-2018-16323", "CVE-2018-16413", "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645", "CVE-2018-16749", "CVE-2018-16750", "CVE-2018-17965", "CVE-2018-17966", "CVE-2018-18016", "CVE-2018-18024");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:35 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 16:49:18 +0000 (Thu, 25 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3348-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183348-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111072");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004773.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:3348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following security issue:

- CVE-2017-17934: Prevent memory leaks, related to MSLPopImage and
 ProcessMSLScript, and associated with mishandling of MSLPushImage calls
 (bsc#1074170).
- CVE-2018-16750: Prevent memory leak in the formatIPTCfromBuffer function
 (bsc#1108283)
- CVE-2018-16749: Added missing NULL check in ReadOneJNGImage that allowed an
 attacker to cause a denial of service (WriteBlob assertion failure and
 application exit) via a crafted file (bsc#1108282)
- CVE-2018-16413: Prevent heap-based buffer over-read in the PushShortPixel
 function leading to DoS (bsc#1106989).
- CVE-2018-16323: ReadXBMImage left data uninitialized when processing an XBM
 file that has a negative pixel value. If the affected code was used as a
 library loaded into a process that includes sensitive information, that
 information sometimes can be leaked via the image data (bsc#1106855)
- CVE-2018-16642: The function InsertRow allowed remote attackers to cause a
 denial of service via a crafted image file due to an out-of-bounds write
 (bsc#1107616)
- CVE-2018-16643: The functions ReadDCMImage, ReadPWPImage, ReadCALSImage, and
 ReadPICTImage did check the return value of the fputc function, which allowed
 remote attackers to cause a denial of service via a crafted image file
 (bsc#1107612)
- CVE-2018-16644: Added missing check for length in the functions ReadDCMImage
 and ReadPICTImage, which allowed remote attackers to cause a denial of service
 via a crafted image (bsc#1107609)
- CVE-2018-16645: Prevent excessive memory allocation issue in the functions
 ReadBMPImage and ReadDIBImage, which allowed remote attackers to cause a denial
 of service via a crafted image file (bsc#1107604)
- CVE-2018-18024: Fixed an infinite loop in the ReadBMPImage function of
 the coders/bmp.c file. Remote attackers could leverage this vulnerability
 to cause a denial of service via a crafted bmp file (bsc#1111069)
- CVE-2018-18016: Fixed a memory leak in WritePCXImage (bsc#1111072)
- CVE-2018-17965: Fixed a memory leak in WriteSGIImage (bsc#1110747)
- CVE-2018-17966: Fixed a memory leak in WritePDBImage (bsc#1110746)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1-32bit", rpm:"libMagickCore1-32bit~6.4.3.6~78.74.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~78.74.1", rls:"SLES11.0SP4"))) {
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
