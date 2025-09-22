# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1851.1");
  script_cve_id("CVE-2017-10928", "CVE-2017-13758", "CVE-2017-18271", "CVE-2018-10804", "CVE-2018-10805", "CVE-2018-11251", "CVE-2018-11655", "CVE-2018-9133");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-15 19:38:31 +0000 (Fri, 15 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1851-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1851-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181851-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095813");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004234.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:1851-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

These security issues were fixed:

- CVE-2017-13758: Prevent heap-based buffer overflow in the TracePoint()
 function (bsc#1056277).
- CVE-2017-10928: Prevent heap-based buffer over-read in the GetNextToken
 function that allowed remote attackers to obtain sensitive information from
 process memory or possibly have unspecified other impact via a crafted SVG
 document (bsc#1047356).
- CVE-2018-9133: Long compute times in the tiff decoder have been fixed (bsc#1087820).
- CVE-2018-11251: Heap-based buffer over-read in ReadSUNImage in coders/sun.c, which allows attackers to cause denial of service (bsc#1094237).
- CVE-2017-18271: Infinite loop in the function ReadMIFFImage in coders/miff.c, which allows attackers to cause a denial of service (bsc#1094204).
- CVE-2018-11655: Memory leak in the GetImagePixelCache in MagickCore/cache.c was fixed (bsc#1095730)
- CVE-2018-10804: Memory leak in WriteTIFFImage in coders/tiff.c was fixed (bsc#1095813)
- CVE-2018-10805: Fixed memory leaks in bgr.c, rgb.c, cmyk.c, gray.c, ycbcr.c (bsc#1095812)");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.65.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.65.1", rls:"SLES12.0SP3"))) {
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
