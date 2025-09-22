# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1489.1");
  script_cve_id("CVE-2017-6502", "CVE-2017-7606", "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2017-8343", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8347", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8356", "CVE-2017-8357", "CVE-2017-8765", "CVE-2017-8830", "CVE-2017-9098", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-02 18:51:37 +0000 (Fri, 02 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1489-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1489-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171489-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040332");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002937.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2017:1489-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

Security issues fixed:

- CVE-2017-6502: Possible file-descriptor leak in libmagickcore that could be triggered via a
 specially crafted webp file (bsc#1028075).
- CVE-2017-7943: The ReadSVGImage function in svg.c allowed remote attackers to consume an
 amount of available memory via a crafted file (bsc#1034870). Note that this only impacts the
 built-in SVG implementation. As we use the librsgv implementation, we are not affected.
- CVE-2017-7942: The ReadAVSImage function in avs.c allowed remote attackers to consume an
 amount of available memory via a crafted file (bsc#1034872).
- CVE-2017-7941: The ReadSGIImage function in sgi.c allowed remote attackers to consume an
 amount of available memory via a crafted file (bsc#1034876).
- CVE-2017-8351: ImageMagick, GraphicsMagick: denial of service (memory leak) via a crafted
 file (ReadPCDImage func in pcd.c) (bsc#1036986).
- CVE-2017-8352: denial of service (memory leak) via a crafted file (ReadXWDImage func in
 xwd.c) (bsc#1036987)
- CVE-2017-8349: denial of service (memory leak) via a crafted file (ReadSFWImage func in
 sfw.c) (bsc#1036984)
- CVE-2017-8350: denial of service (memory leak) via a crafted file (ReadJNGImage function in
 png.c) (bsc#1036985)
- CVE-2017-8347: denial of service (memory leak) via a crafted file (ReadEXRImage func in
 exr.c) (bsc#1036982)
- CVE-2017-8348: denial of service (memory leak) via a crafted file (ReadMATImage func in
 mat.c) (bsc#1036983)
- CVE-2017-8345: denial of service (memory leak) via a crafted file (ReadMNGImage func in
 png.c) (bsc#1036980)
- CVE-2017-8346: denial of service (memory leak) via a crafted file (ReadDCMImage func in
 dcm.c) (bsc#1036981)
- CVE-2017-8353: denial of service (memory leak) via a crafted file (ReadPICTImage func in
 pict.c) (bsc#1036988)
- CVE-2017-8354: denial of service (memory leak) via a crafted file (ReadBMPImage func in
 bmp.c) (bsc#1036989)
- CVE-2017-8830: denial of service (memory leak) via a crafted file (ReadBMPImage func in
 bmp.c:1379) (bsc#1038000)
- CVE-2017-7606: denial of service (application crash) or possibly have unspecified other
 impact via a crafted image (bsc#1033091)
- CVE-2017-8765: memory leak vulnerability via a crafted ICON file (ReadICONImage in
 coders\icon.c) (bsc#1037527)
- CVE-2017-8356: denial of service (memory leak) via a crafted file (ReadSUNImage function in
 sun.c) (bsc#1036991)
- CVE-2017-8355: denial of service (memory leak) via a crafted file (ReadMTVImage func in
 mtv.c) (bsc#1036990)
- CVE-2017-8344: denial of service (memory leak) via a crafted file (ReadPCXImage func in
 pcx.c) (bsc#1036978)
- CVE-2017-8343: denial of service (memory leak) via a crafted file (ReadAAIImage func in
 aai.c) (bsc#1036977)
- CVE-2017-8357: denial of service (memory leak) via a crafted file (ReadEPTImage func in
 ept.c) (bsc#1036976)
- CVE-2017-9098: uninitialized memory ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~70.1", rls:"SLES12.0SP2"))) {
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
