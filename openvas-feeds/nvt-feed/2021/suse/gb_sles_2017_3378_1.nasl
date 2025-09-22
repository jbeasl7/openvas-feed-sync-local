# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3378.1");
  script_cve_id("CVE-2017-11188", "CVE-2017-11478", "CVE-2017-11527", "CVE-2017-11535", "CVE-2017-11640", "CVE-2017-11752", "CVE-2017-12140", "CVE-2017-12435", "CVE-2017-12587", "CVE-2017-12644", "CVE-2017-12662", "CVE-2017-12669", "CVE-2017-12983", "CVE-2017-13134", "CVE-2017-13769", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14175", "CVE-2017-14341", "CVE-2017-14342", "CVE-2017-14531", "CVE-2017-14607", "CVE-2017-14733", "CVE-2017-15930", "CVE-2017-16545", "CVE-2017-16546");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:50 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-07 13:08:17 +0000 (Tue, 07 Nov 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3378-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3378-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173378-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067184");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-December/003541.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2017:3378-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

 * CVE-2017-14607: out of bounds read flaw related to ReadTIFFImagehas
 could possibly disclose potentially sensitive memory [bsc#1059778]

 * CVE-2017-11640: NULL pointer deref in WritePTIFImage() in coders/tiff.c [bsc#1050632]

 * CVE-2017-14342: a memory exhaustion vulnerability in ReadWPGImage
 in coders/wpg.c could lead to denial of service [bsc#1058485]

 * CVE-2017-14341: Infinite loop in the ReadWPGImage function [bsc#1058637]

 * CVE-2017-16546: problem in the function ReadWPGImage in coders/wpg.c
 could lead to denial of service [bsc#1067181]

 * CVE-2017-16545: The ReadWPGImage function in coders/wpg.c in
 validation problems could lead to denial of service [bsc#1067184]

 * CVE-2017-14175: Lack of End of File check could lead to denial of service [bsc#1057719]

 * CVE-2017-13769: denial of service issue in function WriteTHUMBNAILImage in coders/thumbnail.c [bsc#1056432]

 * CVE-2017-13134: a heap-based buffer over-read was found in thefunction SFWScan
 in coders/sfw.c, which allows attackers to cause adenial of service via a crafted file. [bsc#1055214]

 * CVE-2017-11478: ReadOneDJVUImage in coders/djvu.c in ImageMagick allows remote attackers to cause a DoS [bsc#1049796]

 * CVE-2017-15930: Null Pointer dereference while transfering JPEG scanlines could lead to denial of service [bsc#1066003]

 * CVE-2017-12983: Heap-based buffer overflow in the ReadSFWImage function in coders/sfw.c
 allows remote attackers to cause a denial of service [bsc#1054757]

 * CVE-2017-14531: memory exhaustion issue in ReadSUNImage incoders/sun.c. [bsc#1059666]

 * CVE-2017-12435: Memory exhaustion in ReadSUNImage in coders/sun.c,
 which allows attackers to cause denial of service [bsc#1052553]

 * CVE-2017-12587: User controlable large loop in the ReadPWPImage in coders\pwp.c could lead to denial of service [bsc#1052450]

 * CVE-2017-14173: unction ReadTXTImage is vulnerable to a integer overflow that could lead to denial of service [bsc#1057729]

 * CVE-2017-11188: ImageMagick: The ReadDPXImage function in codersdpx.c in ImageMagick 7.0.6-0 has a largeloop vulnerability that can cause CPU exhaustion via a crafted DPX file, relatedto lack of an EOF check. [bnc#1048457]

 * CVE-2017-11527: ImageMagick: ReadDPXImage in coders/dpx.c allows remote attackers to cause DoS [bnc#1050116]

 * CVE-2017-11535: GraphicsMagick, ImageMagick: Heap-based buffer over-read in WritePSImage() in coders/ps.c [bnc#1050139]

 * CVE-2017-11752: ImageMagick: ReadMAGICKImage in coders/magick.c allows to cause DoS [bnc#1051441]

 * CVE-2017-12140: ImageMagick: ReadDCMImage in codersdcm.c has a ninteger signedness error leading to excessive memory consumption [bnc#1051847]

 * CVE-2017-12669: ImageMagick: Memory leak in WriteCALSImage in coders/cals.c [bnc#1052689]

 * CVE-2017-12662: GraphicsMagick, ImageMagick: Memory leak in WritePDFImage in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1-32bit", rpm:"libMagickCore1-32bit~6.4.3.6~7.78.14.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~7.78.14.1", rls:"SLES11.0SP4"))) {
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
