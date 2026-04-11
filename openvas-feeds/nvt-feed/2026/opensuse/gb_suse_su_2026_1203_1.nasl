# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1203.1");
  script_cve_id("CVE-2026-28493", "CVE-2026-28494", "CVE-2026-28686", "CVE-2026-28687", "CVE-2026-28688", "CVE-2026-28689", "CVE-2026-28690", "CVE-2026-28691", "CVE-2026-28692", "CVE-2026-28693", "CVE-2026-30883", "CVE-2026-30929", "CVE-2026-30935", "CVE-2026-30936", "CVE-2026-30937", "CVE-2026-31853", "CVE-2026-32259", "CVE-2026-32636", "CVE-2026-33535", "CVE-2026-33536");
  script_tag(name:"creation_date", value:"2026-04-09 04:48:59 +0000 (Thu, 09 Apr 2026)");
  script_version("2026-04-09T06:11:03+0000");
  script_tag(name:"last_modification", value:"2026-04-09 06:11:03 +0000 (Thu, 09 Apr 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-13 17:02:14 +0000 (Fri, 13 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1203-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1203-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261203-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260879");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045301.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2026:1203-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2026-28493: integer overflow in the SIXEL decoder leads to out-of-bounds write (bsc#1259446).
- CVE-2026-28494: missing bounds checks in the morphology kernel parsing functions can lead to a stack buffer overflow
 (bsc#1259447).
- CVE-2026-28686: undersized output buffer allocation in the PCL encoder can lead to a heap buffer overflow
 (bsc#1259448).
- CVE-2026-28687: heap use-after-free vulnerability in the MSL decoder via a crafted MSL file (bsc#1259450).
- CVE-2026-28688: heap use-after-free in the MSL encoder when a cloned image is destroyed twice (bsc#1259451).
- CVE-2026-28689: `domain='path'` authorization is checked before final file open/use and allows for read/write bypass
 via symlink swaps (bsc#1259452).
- CVE-2026-28690: missing bounds check in the MNG encoder can lead to a stack buffer overflow (bsc#1259456).
- CVE-2026-28691: missing check in the JBIG decoder can lead to an uninitialized pointer dereference (bsc#1259455).
- CVE-2026-28692: 32-bit integer overflow in MAT decoder can lead to a heap buffer over-read (bsc#1259457).
- CVE-2026-28693: integer overflow in the DIB coder can lead to an out-of-bounds read or write (bsc#1259466).
- CVE-2026-30883: missing bounds check when encoding a PNG image can lead to a heap buffer over-write (bsc#1259467).
- CVE-2026-30929: improper use of fixed-size stack buffer in `MagnifyImage`can lead to a stack buffer overflow
 (bsc#1259468).
- CVE-2026-30935: heap-based buffer over-read in BilateralBlurImage (bsc#1259497).
- CVE-2026-30936: Heap Buffer Overflow in WaveletDenoiseImage (bsc#1259464).
- CVE-2026-30937: Heap buffer overflow in XWD encoder due to CARD32 arithmetic overflow (bsc#1259463).
- CVE-2026-31853: heap buffer overflow leads to crash in the SFW decoder of 32-bit systems when processing extremely
 large images (bsc#1259528).
- CVE-2026-32259: memory allocation fails can lead to out of bound write (bsc#1259612).
- CVE-2026-32636: Denial of Service via out-of-bounds write in NewXMLTree method (bsc#1259872).
- CVE-2026-33535: Out-of-Bounds write of a zero byte in X11 display interaction (bsc#1260874).
- CVE-2026-33536: Denial of Service via out-of-bounds write (bsc#1260879).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-SUSE", rpm:"ImageMagick-config-7-SUSE~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-limited", rpm:"ImageMagick-config-7-upstream-limited~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-open", rpm:"ImageMagick-config-7-upstream-open~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-secure", rpm:"ImageMagick-config-7-upstream-secure~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-websafe", rpm:"ImageMagick-config-7-upstream-websafe~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5-32bit", rpm:"libMagick++-7_Q16HDRI5-32bit~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5", rpm:"libMagick++-7_Q16HDRI5~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10-32bit", rpm:"libMagickCore-7_Q16HDRI10-32bit~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10", rpm:"libMagickCore-7_Q16HDRI10~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10-32bit", rpm:"libMagickWand-7_Q16HDRI10-32bit~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10", rpm:"libMagickWand-7_Q16HDRI10~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~7.1.1.21~150600.3.50.1", rls:"openSUSELeap15.6"))) {
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
