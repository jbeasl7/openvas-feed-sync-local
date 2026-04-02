# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0852.1");
  script_cve_id("CVE-2026-24481", "CVE-2026-24484", "CVE-2026-24485", "CVE-2026-25576", "CVE-2026-25637", "CVE-2026-25638", "CVE-2026-25795", "CVE-2026-25796", "CVE-2026-25797", "CVE-2026-25798", "CVE-2026-25799", "CVE-2026-25897", "CVE-2026-25898", "CVE-2026-25965", "CVE-2026-25966", "CVE-2026-25967", "CVE-2026-25968", "CVE-2026-25969", "CVE-2026-25970", "CVE-2026-25971", "CVE-2026-25983", "CVE-2026-25985", "CVE-2026-25986", "CVE-2026-25987", "CVE-2026-25988", "CVE-2026-25989", "CVE-2026-26066", "CVE-2026-26284", "CVE-2026-26983", "CVE-2026-27798", "CVE-2026-27799");
  script_tag(name:"creation_date", value:"2026-03-11 04:35:18 +0000 (Wed, 11 Mar 2026)");
  script_version("2026-03-12T05:56:11+0000");
  script_tag(name:"last_modification", value:"2026-03-12 05:56:11 +0000 (Thu, 12 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 15:53:11 +0000 (Wed, 25 Feb 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0852-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260852-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259018");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024664.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2026:0852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2026-24481: Possible Heap Information Disclosure in PSD ZIP Decompression (bsc#1258743).
- CVE-2026-24484: denial of service vulnerability via multi-layer nested MVG to SVG conversion (bsc#1258790).
- CVE-2026-24485: denial of service via malformed PCD file processing (bsc#1258791).
- CVE-2026-25576: Out of bounds read in multiple coders that read raw pixel data (bsc#1258748).
- CVE-2026-25637: Denial of Service via crafted image due to memory leak (bsc#1258759).
- CVE-2026-25638: Denial of Service due to memory leak in image processing (bsc#1258793).
- CVE-2026-25795: Denial of Service due to NULL pointer dereference during temporary file creation failure
 (bsc#1258792).
- CVE-2026-25796: Memory leak of watermark Image object in ReadSTEGANOImage on multiple error/early-return paths
 (bsc#1258757).
- CVE-2026-25797: Code injection in various encoders (bsc#1258770).
- CVE-2026-25798: NULL Pointer Dereference in ClonePixelCacheRepository via crafted image (bsc#1258787).
- CVE-2026-25799: Division-by-Zero in YUV sampling factor validation leads to crash (bsc#1258786).
- CVE-2026-25897: Out-of-bounds heap write via integer overflow in sun decoder (bsc#1258799).
- CVE-2026-25898: Information disclosure or denial of service via crafted image with invalid pixel index (bsc#1258807).
- CVE-2026-25965: Policy bypass through path traversal allows reading restricted content despite secured policy
 (bsc#1258785).
- CVE-2026-25966: Security Policy Bypass through config/policy-secure.xml via 'fd handler' leads to stdin/stdout access
 (bsc#1258780).
- CVE-2026-25967: Stack buffer overflow in FTXT reader via oversized integer field (bsc#1258779).
- CVE-2026-25968: MSL attribute stack buffer overflow leads to out of bounds write (bsc#1258776).
- CVE-2026-25969: Memory Leak in coders/ashlar.c (bsc#1258775).
- CVE-2026-25970: Memory corruption and denial of service via signed integer overflow in SIXEL decoder (bsc#1258802).
- CVE-2026-25971: MSL: Stack overflow in ProcessMSLScript (bsc#1258774).
- CVE-2026-25983: Denial of service via crafted MSL script (bsc#1258805).
- CVE-2026-25985: Memory allocation with excessive without limits in the internal SVG decoder (bsc#1258812).
- CVE-2026-25986: Denial of Service via malicious YUV image processing (bsc#1258818).
- CVE-2026-25987: Memory disclosure and denial of service via crafted MAP files (bsc#1258821).
- CVE-2026-25988: Denial of Service due to memory leak in image processing (bsc#1258810).
- CVE-2026-25989: Integer overflow or wraparound and incorrect conversion between numeric types in the internal SVG
 decoder (bsc#1258771).
- CVE-2026-26066: Infinite loop when writing IPTCTEXT leads to denial of service via crafted profile (bsc#1258769).
- CVE-2026-26284: Heap overflow in pcd decoder leads to out of bounds read (bsc#1258765).
- CVE-2026-26983: Invalid MSL <map> can result in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-SUSE", rpm:"ImageMagick-config-7-SUSE~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-limited", rpm:"ImageMagick-config-7-upstream-limited~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-open", rpm:"ImageMagick-config-7-upstream-open~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-secure", rpm:"ImageMagick-config-7-upstream-secure~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-websafe", rpm:"ImageMagick-config-7-upstream-websafe~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5-32bit", rpm:"libMagick++-7_Q16HDRI5-32bit~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5", rpm:"libMagick++-7_Q16HDRI5~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10-32bit", rpm:"libMagickCore-7_Q16HDRI10-32bit~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10", rpm:"libMagickCore-7_Q16HDRI10~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10-32bit", rpm:"libMagickWand-7_Q16HDRI10-32bit~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10", rpm:"libMagickWand-7_Q16HDRI10~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~7.1.1.21~150600.3.42.2", rls:"openSUSELeap15.6"))) {
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
