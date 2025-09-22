# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3388.1");
  script_cve_id("CVE-2017-11188", "CVE-2017-11478", "CVE-2017-11523", "CVE-2017-11527", "CVE-2017-11535", "CVE-2017-11640", "CVE-2017-11752", "CVE-2017-12140", "CVE-2017-12435", "CVE-2017-12587", "CVE-2017-12644", "CVE-2017-12662", "CVE-2017-12669", "CVE-2017-12983", "CVE-2017-13134", "CVE-2017-13769", "CVE-2017-14138", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14175", "CVE-2017-14341", "CVE-2017-14342", "CVE-2017-14531", "CVE-2017-14607", "CVE-2017-14682", "CVE-2017-14733", "CVE-2017-14989", "CVE-2017-15217", "CVE-2017-15930", "CVE-2017-16545", "CVE-2017-16546", "CVE-2017-16669");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-06 14:37:57 +0000 (Wed, 06 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3388-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173388-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067409");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-December/003544.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2017:3388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

 * CVE-2017-14989: use-after-free in RenderFreetype in MagickCore/annotate.c could lead to denial of service [bsc#1061254]
 * CVE-2017-14682: GetNextToken in MagickCore/token.c heap buffer overflow could lead to denial of service [bsc#1060176]
 * Memory leak in WriteINLINEImage in coders/inline.c could lead to denial of service [bsc#1052744]
 * CVE-2017-14607: out of bounds read flaw related to ReadTIFFImagehas could possibly disclose potentially sensitive memory [bsc#1059778]
 * CVE-2017-11640: NULL pointer deref in WritePTIFImage() in coders/tiff.c [bsc#1050632]
 * CVE-2017-14342: a memory exhaustion vulnerability in ReadWPGImage in coders/wpg.c could lead to denial of service [bsc#1058485]
 * CVE-2017-14341: Infinite loop in the ReadWPGImage function [bsc#1058637]
 * CVE-2017-16546: problem in the function ReadWPGImage in coders/wpg.c could lead to denial of service [bsc#1067181]
 * CVE-2017-16545: The ReadWPGImage function in coders/wpg.c in validation problems could lead to denial of service [bsc#1067184]
 * CVE-2017-16669: problem in coders/wpg.c could allow remote attackers to cause a denial of service via crafted file [bsc#1067409]
 * CVE-2017-14175: Lack of End of File check could lead to denial of service [bsc#1057719]
 * CVE-2017-14138: memory leak vulnerability in ReadWEBPImage in coders/webp.c could lead to denial of service [bsc#1057157]
 * CVE-2017-13769: denial of service issue in function WriteTHUMBNAILImage in coders/thumbnail.c [bsc#1056432]
 * CVE-2017-13134: a heap-based buffer over-read was found in thefunction SFWScan in coders/sfw.c, which allows attackers to cause adenial of service via a crafted file. [bsc#1055214]
 * CVE-2017-15217: memory leak in ReadSGIImage in coders/sgi.c [bsc#1062750]
 * CVE-2017-11478: ReadOneDJVUImage in coders/djvu.c in ImageMagick allows remote attackers to cause a DoS [bsc#1049796]
 * CVE-2017-15930: Null Pointer dereference while transfering JPEG scanlines could lead to denial of service [bsc#1066003]
 * CVE-2017-12983: Heap-based buffer overflow in the ReadSFWImage function in coders/sfw.c inImageMagick 7.0.6-8 allows remote attackers to cause a denial of service [bsc#1054757]
 * CVE-2017-14531: memory exhaustion issue in ReadSUNImage incoders/sun.c. [bsc#1059666]
 * CVE-2017-12435: Memory exhaustion in ReadSUNImage in coders/sun.c, which allows attackers to cause denial of service [bsc#1052553]
 * CVE-2017-12587: User controlable large loop in the ReadPWPImage in coders\pwp.c could lead to denial of service [bsc#1052450]
 * CVE-2017-11523: ReadTXTImage in coders/txt.c allows remote attackers to cause a denial of service [bsc#1050083]
 * CVE-2017-14173: unction ReadTXTImage is vulnerable to a integer overflow that could lead to denial of service [bsc#1057729]
 * CVE-2017-11188: ImageMagick: The ReadDPXImage function in codersdpx.c in ImageMagick 7.0.6-0 has a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.17.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.17.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.17.1", rls:"SLES12.0SP3"))) {
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
