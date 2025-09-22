# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3095.1");
  script_cve_id("CVE-2017-11532", "CVE-2018-16413", "CVE-2018-16640", "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645", "CVE-2018-16749", "CVE-2018-16750");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 16:49:18 +0000 (Thu, 25 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3095-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183095-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108283");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004662.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:3095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following security issues:

- CVE-2017-11532: Prevent a memory leak vulnerability in the WriteMPCImage()
 function in coders/mpc.c via a crafted file allowing for DoS (bsc#1050129)
- CVE-2018-16750: Prevent memory leak in the formatIPTCfromBuffer function
 (bsc#1108283)
- CVE-2018-16749: Added missing NULL check in ReadOneJNGImage that allowed an
 attacker to cause a denial of service (WriteBlob assertion failure and
 application exit) via a crafted file (bsc#1108282)
- CVE-2018-16642: The function InsertRow allowed remote attackers to cause a
 denial of service via a crafted image file due to an out-of-bounds write
 (bsc#1107616)
- CVE-2018-16640: Prevent memory leak in the function ReadOneJNGImage
 (bsc#1107619)
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
- CVE-2018-16413: Prevent heap-based buffer over-read in the PushShortPixel
 function leading to DoS (bsc#1106989)

This update also relaxes the restrictions of use of Postscript like formats to
'write' only. (bsc#1105592)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.79.1", rls:"SLES12.0SP3"))) {
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
