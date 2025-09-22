# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1128.1");
  script_cve_id("CVE-2020-22037", "CVE-2024-12361", "CVE-2024-35368", "CVE-2024-36613", "CVE-2025-0518", "CVE-2025-22919", "CVE-2025-22921", "CVE-2025-25473");
  script_tag(name:"creation_date", value:"2025-04-07 04:07:00 +0000 (Mon, 07 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-07 15:36:15 +0000 (Mon, 07 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1128-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251128-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237382");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038897.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg-4' package(s) announced via the SUSE-SU-2025:1128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 fixes the following issues:


- CVE-2020-22037: Fixed unchecked return value of the init_vlc function (bsc#1186756)
- CVE-2024-12361: Fixed null pointer dereference (bsc#1237358)
- CVE-2024-35368: Fixed double free via the rkmpp_retrieve_frame function within libavcodec/rkmppdec.c (bsc#1234028)
- CVE-2024-36613: Fixed integer overflow in the DXA demuxer of the libavformat library (bsc#1235092)
- CVE-2025-0518: Fixed memory leak due to unchecked sscanf return value (bsc#1236007)
- CVE-2025-22919: Fixed denial of service (DoS) via opening a crafted AAC file (bsc#1237371)
- CVE-2025-22921: Fixed segmentation violation in NULL pointer dereference via the component /libavcodec/jpeg2000dec.c (bsc#1237382)
- CVE-2025-25473: Fixed memory leak in avformat_free_context() (bsc#1237351)

Other fixes:

- Build with SVT-AV1 3.0.0.

- Update to release 4.4.5:
* Adjust bconds to build the package in SLFO without xvidcore.
* Add 0001-libavcodec-arm-mlpdsp_armv5te-fix-label-format-to-wo.patch (bsc#1229338)
* Add ffmpeg-c99.patch so that the package conforms to the C99 standard and builds on i586 with GCC 14.
* No longer build against libmfx, build against libvpl (bsc#1230983, bsc#1219494)
* Drop libmfx dependency from our product (jira #PED-10024)
* Update patch to build with glslang 14
* Disable vmaf integration as ffmpeg-4 cannot handle vmaf>=3
* Copy codec list from ffmpeg-6
* Resolve build failure with binutils >= 2.41. (bsc#1215945)

- Update to version 4.4.4:
 * avcodec/012v: Order operations for odd size handling
 * avcodec/alsdec: The minimal block is at least 7 bits
 * avcodec/bink:
 - Avoid undefined out of array end pointers in
 binkb_decode_plane()
 - Fix off by 1 error in ref end
 * avcodec/eac3dec: avoid float noise in fixed mode addition to
 overflow
 * avcodec/eatgq: : Check index increments in tgq_decode_block()
 * avcodec/escape124:
 - Fix signdness of end of input check
 - Fix some return codes
 * avcodec/ffv1dec:
 - Check that num h/v slices is supported
 - Fail earlier if prior context is corrupted
 - Restructure slice coordinate reading a bit
 * avcodec/mjpegenc: take into account component count when
 writing the SOF header size
 * avcodec/mlpdec: Check max matrix instead of max channel in
 noise check
 * avcodec/motionpixels: Mask pixels to valid values
 * avcodec/mpeg12dec: Check input size
 * avcodec/nvenc:
 - Fix b-frame DTS behavior with fractional framerates
 - Fix vbv buffer size in cq mode
 * avcodec/pictordec: Remove mid exit branch
 * avcodec/pngdec: Check deloco index more exactly
 * avcodec/rpzaenc: stop accessing out of bounds frame
 * avcodec/scpr3: Check bx
 * avcodec/scpr: Test bx before use
 * avcodec/snowenc: Fix visual weight calculation
 * avcodec/speedhq: Check buf_size to be big enough for DC
 * avcodec/sunrast: Fix maplength check
 * avcodec/tests/snowenc:
 - Fix 2nd test
 - Return a failure if DWT/IDWT mismatches
 - ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ffmpeg-4' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134", rpm:"libavcodec58_134~4.4.5~150400.3.46.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76", rpm:"libavformat58_76~4.4.5~150400.3.46.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70", rpm:"libavutil56_70~4.4.5~150400.3.46.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9", rpm:"libpostproc55_9~4.4.5~150400.3.46.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9", rpm:"libswresample3_9~4.4.5~150400.3.46.1", rls:"SLES15.0SP4"))) {
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
