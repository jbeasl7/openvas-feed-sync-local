# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4333.1");
  script_cve_id("CVE-2023-6879");
  script_tag(name:"creation_date", value:"2024-12-17 04:17:13 +0000 (Tue, 17 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 16:26:26 +0000 (Fri, 05 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4333-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244333-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/020010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libaom, libyuv' package(s) announced via the SUSE-SU-2024:4333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- aomedia:3349: heap overflow when increasing resolution
 - aomedia:3478: GCC 12.2.0 emits a -Wstringop-overflow warning
 on aom/av1/encoder/motion_search_facade.c
 - aomedia:3489: Detect encoder and image high bit depth
 mismatch
 - aomedia:3491: heap-buffer-overflow on frame size change
 - b/303023614: Segfault at encoding time for high bit depth
 images

- New upstream release 3.7.0

 - New Features

 * New codec controls:

 * AV1E_SET_QUANTIZER_ONE_PASS: Set quantizer for each frame.
 * AV1E_ENABLE_RATE_GUIDE_DELTAQ: enable the rate distribution guided delta
 quantization in all intra mode. The 'enable-rate-guide-deltaq' option is
 added for this control.
 * AV1E_SET_RATE_DISTRIBUTION_INFO: set the input file for rate
 distribution used in all intra mode. The 'rate-distribution-info' option
 is added for this control.
 * AV1E_GET_LUMA_CDEF_STRENGTH
 * AV1E_SET_BITRATE_ONE_PASS_CBR

 * AOM_SCALING_MODE is extended to include 2/3 and 1/3 scaling.
 * aom_tune_metric is extended to include AOM_TUNE_VMAF_SALIENCY_MAP.
 The 'tune' option is extended to include 'vmaf_saliency_map'.
 * SVC example encoder svc_encoder_rtc is able to use the rate control
 library.
 * Loopfilter level and CDEF filter level is supported by RTC rate control
 library.
 * New speed (--cpu-used) 11, intended for RTC screen sharing, added for
 faster encoding with ~3% bdrate loss with 16% IC (instruction count)
 speedup compared to speed 10.

 - Compression Efficiency Improvements

 * Improved VoD encoding performance

 * 0.1-0.6% BDrate gains for encoding speeds 2 to 6
 * Rate control accuracy improvement in VBR mode

 * RTC encoding improvements

 * Screen content mode: 10-19% BDrate gains for speeds 6 - 10
 * Temporal layers video mode, for speed 10:

 * 2 temporal layers on low resolutions: 13-15% BDrate gain
 * 3 temporal layers on VGA/HD: 3-4% BDrate gain

 - Perceptual Quality Improvements

 * Fixed multiple block and color artifacts for RTC screen content by

 * Incorporating color into RD cost for IDTX
 * Reducing thresholds for palette mode in non RD mode
 * Allowing more palette mode testing

 * Improved color sensitivity for altref in non-RD mode.
 * Reduced video flickering for temporal layer encoding.

 - Speedup and Memory Optimizations

 * Speed up the VoD encoder

 * 2-5% for encoding speed 2 to 4
 * 9-15% for encoding speed 5 to 6
 * ARM

 * Standard bitdepth

 * speed 5: +31%
 * speed 4: +2%
 * speed 3: +9%
 * speed 2: +157%

 * High bitdepth

 * speed 5: +85%

 * RTC speedups

 * Screen content mode

 * 15% IC speedup for speeds 6-8
 * ARM: 7% for speed 9, 3% for speed 10

 * Temporal layers video mode

 * 7% speedup for 3 temporal layers on VGA/HD, for speed 10

 * Single layer video

 * x86: 2% IC speedup for speeds 7-10
 * ARM: 2-4% speedup across speeds 5-10

 - Bug Fixes

 * aomedia:3261 Assertion failed when encoding av1 with film grain and
 '--monochrome' flag
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libaom, libyuv' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"aom-tools", rpm:"aom-tools~3.7.1~150400.3.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel", rpm:"libaom-devel~3.7.1~150400.3.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel-doc", rpm:"libaom-devel-doc~3.7.1~150400.3.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3", rpm:"libaom3~3.7.1~150400.3.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyuv-devel", rpm:"libyuv-devel~20230517+a377993~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyuv-tools", rpm:"libyuv-tools~20230517+a377993~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libyuv0", rpm:"libyuv0~20230517+a377993~150400.9.3.1", rls:"SLES15.0SP4"))) {
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
