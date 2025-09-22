# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0199.1");
  script_cve_id("CVE-2020-19667", "CVE-2020-25664", "CVE-2020-25665", "CVE-2020-25666", "CVE-2020-25674", "CVE-2020-25675", "CVE-2020-25676", "CVE-2020-27750", "CVE-2020-27751", "CVE-2020-27752", "CVE-2020-27753", "CVE-2020-27754", "CVE-2020-27755", "CVE-2020-27757", "CVE-2020-27759", "CVE-2020-27760", "CVE-2020-27761", "CVE-2020-27762", "CVE-2020-27763", "CVE-2020-27764", "CVE-2020-27765", "CVE-2020-27766", "CVE-2020-27767", "CVE-2020-27768", "CVE-2020-27769", "CVE-2020-27770", "CVE-2020-27771", "CVE-2020-27772", "CVE-2020-27773", "CVE-2020-27774", "CVE-2020-27775", "CVE-2020-27776");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 15:23:05 +0000 (Mon, 07 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0199-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0199-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210199-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179397");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-January/008240.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2021:0199-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2020-19667: Fixed a stack buffer overflow in XPM coder could result in a crash (bsc#1179103).
- CVE-2020-25664: Fixed a heap-based buffer overflow in PopShortPixel (bsc#1179202).
- CVE-2020-25665: Fixed a heap-based buffer overflow in WritePALMImage (bsc#1179208).
- CVE-2020-25666: Fixed an outside the range of representable values of type 'int' and signed integer overflow (bsc#1179212).
- CVE-2020-25674: Fixed a heap-based buffer overflow in WriteOnePNGImage (bsc#1179223).
- CVE-2020-25675: Fixed an outside the range of representable values of type 'long' and integer overflow (bsc#1179240).
- CVE-2020-25676: Fixed an outside the range of representable values of type 'long' and integer overflow at MagickCore/pixel.c (bsc#1179244).
- CVE-2020-27750: Fixed an division by zero in MagickCore/colorspace-private.h (bsc#1179260).
- CVE-2020-27751: Fixed an integer overflow in MagickCore/quantum-export.c (bsc#1179269).
- CVE-2020-27752: Fixed a heap-based buffer overflow in PopShortPixel in MagickCore/quantum-private.h (bsc#1179346).
- CVE-2020-27753: Fixed memory leaks in AcquireMagickMemory function (bsc#1179397).
- CVE-2020-27754: Fixed an outside the range of representable values of type 'long' and signed integer overflow at MagickCore/quantize.c (bsc#1179336).
- CVE-2020-27755: Fixed memory leaks in ResizeMagickMemory function in ImageMagick/MagickCore/memory.c (bsc#1179345).
- CVE-2020-27757: Fixed an outside the range of representable values of type 'unsigned long long' at MagickCore/quantum-private.h (bsc#1179268).
- CVE-2020-27759: Fixed an outside the range of representable values of type 'int' at MagickCore/quantize.c (bsc#1179313).
- CVE-2020-27760: Fixed a division by zero at MagickCore/enhance.c (bsc#1179281).
- CVE-2020-27761: Fixed an outside the range of representable values of type 'unsigned long' at coders/palm.c (bsc#1179315).
- CVE-2020-27762: Fixed an outside the range of representable values of type 'unsigned char' (bsc#1179278).
- CVE-2020-27763: Fixed a division by zero at MagickCore/resize.c (bsc#1179312).
- CVE-2020-27764: Fixed an outside the range of representable values of type 'unsigned long' at MagickCore/statistic.c (bsc#1179317).
- CVE-2020-27765: Fixed a division by zero at MagickCore/segment.c (bsc#1179311).
- CVE-2020-27766: Fixed an outside the range of representable values of type 'unsigned long' at MagickCore/statistic.c (bsc#1179361).
- CVE-2020-27767: Fixed an outside the range of representable values of type 'float' at MagickCore/quantum.h (bsc#1179322).
- CVE-2020-27768: Fixed an outside the range of representable values of type 'unsigned int' at MagickCore/quantum-private.h (bsc#1179339).
- CVE-2020-27769: Fixed an outside the range of representable values of type 'float' at MagickCore/quantize.c (bsc#1179321).
- CVE-2020-27770: Fixed an unsigned offset overflowed at ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.154.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.154.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.154.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.154.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.154.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.154.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-SUSE", rpm:"ImageMagick-config-6-SUSE~6.8.8.1~71.154.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-6-upstream", rpm:"ImageMagick-config-6-upstream~6.8.8.1~71.154.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~71.154.1", rls:"SLES12.0SP5"))) {
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
