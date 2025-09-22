# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0581.1");
  script_cve_id("CVE-2017-11166", "CVE-2017-11170", "CVE-2017-11448", "CVE-2017-11450", "CVE-2017-11528", "CVE-2017-11530", "CVE-2017-11531", "CVE-2017-11533", "CVE-2017-11537", "CVE-2017-11638", "CVE-2017-11642", "CVE-2017-12418", "CVE-2017-12427", "CVE-2017-12429", "CVE-2017-12432", "CVE-2017-12566", "CVE-2017-12654", "CVE-2017-12663", "CVE-2017-12664", "CVE-2017-12665", "CVE-2017-12668", "CVE-2017-12674", "CVE-2017-13058", "CVE-2017-13131", "CVE-2017-14060", "CVE-2017-14139", "CVE-2017-14224", "CVE-2017-17682", "CVE-2017-17885", "CVE-2017-17934", "CVE-2017-18028", "CVE-2017-9405", "CVE-2017-9407", "CVE-2018-5357", "CVE-2018-6405");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-18 13:57:27 +0000 (Mon, 18 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0581-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0581-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180581-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078433");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003769.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2018:0581-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2017-9405: A memory leak in the ReadICONImage function was fixed that could lead to DoS via memory exhaustion (bsc#1042911)
- CVE-2017-9407: In ImageMagick, the ReadPALMImage function in palm.c allowed attackers to cause a denial of service (memory leak) via a crafted file. (bsc#1042824)
- CVE-2017-11166: In ReadXWDImage in coders\xwd.c a memoryleak could have caused memory exhaustion via a crafted length (bsc#1048110)
- CVE-2017-11170: ReadTGAImage in coders\tga.c allowed for memory exhaustion via invalid colors data in the header of a TGA or VST file (bsc#1048272)
- CVE-2017-11448: The ReadJPEGImage function in coders/jpeg.c in ImageMagick allowed remote attackers to obtain sensitive information from uninitialized memory locations via a crafted file. (bsc#1049375)
- CVE-2017-11450: A remote denial of service in coders/jpeg.c was fixed (bsc#1049374)
- CVE-2017-11528: ReadDIBImage in coders/dib.c allows remote attackers to cause DoS via memory exhaustion (bsc#1050119)
- CVE-2017-11530: ReadEPTImage in coders/ept.c allows remote attackers to cause DoS via memory exhaustion (bsc#1050122)
- CVE-2017-11531: When ImageMagick processed a crafted file in convert, it could lead to a Memory Leak in the WriteHISTOGRAMImage() function in coders/histogram.c. (bsc#1050126)
- CVE-2017-11533: A information leak by 1 byte due to heap-based buffer over-read in the WriteUILImage() in coders/uil.c was fixed (bsc#1050132)
- CVE-2017-11537: When ImageMagick processed a crafted file in convert, it can lead to a Floating Point Exception (FPE) in the WritePALMImage() function in coders/palm.c, related to an incorrect bits-per-pixel calculation. (bsc#1050048)
- CVE-2017-11638, CVE-2017-11642: A NULL pointer dereference in theWriteMAPImage() in coders/map.c was fixed which could lead to a crash (bsc#1050617)
- CVE-2017-12418: ImageMagick had memory leaks in the parse8BIMW and format8BIM functions in coders/meta.c, related to the WriteImage function in MagickCore/constitute.c. (bsc#1052207)
- CVE-2017-12427: ProcessMSLScript coders/msl.c allowed remote attackers to cause a DoS (bsc#1052248)
- CVE-2017-12429: A memory exhaustion flaw in ReadMIFFImage in coders/miff.c was fixed, which allowed attackers to cause DoS (bsc#1052251)
- CVE-2017-12432: In ImageMagick, a memory exhaustion vulnerability was found in the function ReadPCXImage in coders/pcx.c, which allowed attackers to cause a denial of service. (bsc#1052254)
- CVE-2017-12566: A memory leak in ReadMVGImage in coders/mvg.c, could have allowed attackers to cause DoS (bsc#1052472)
- CVE-2017-12654: The ReadPICTImage function in coders/pict.c in ImageMagick allowed attackers to cause a denial of service (memory leak) via a crafted file. (bsc#1052761)
- CVE-2017-12663: A memory leak in WriteMAPImage in coders/map.c was fixed that could lead to a DoS via memory exhaustion ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.42.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.42.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.42.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.42.1", rls:"SLES12.0SP3"))) {
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
