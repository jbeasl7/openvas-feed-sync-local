# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0862.1");
  script_cve_id("CVE-2023-49502", "CVE-2023-50010", "CVE-2023-51793", "CVE-2023-51794", "CVE-2023-51798", "CVE-2024-12361", "CVE-2024-31578", "CVE-2024-32230", "CVE-2024-35368", "CVE-2024-36613", "CVE-2024-7055", "CVE-2025-0518", "CVE-2025-22919", "CVE-2025-22921", "CVE-2025-25473");
  script_tag(name:"creation_date", value:"2025-03-17 15:24:00 +0000 (Mon, 17 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-03 17:20:06 +0000 (Tue, 03 Jun 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0862-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0862-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250862-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237382");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020516.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg-4' package(s) announced via the SUSE-SU-2025:0862-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 fixes the following issues:

- CVE-2025-22921: Fixed segmentation violation in NULL pointer dereference via the component /libavcodec/jpeg2000dec.c (bsc#1237382).
- CVE-2025-25473: Fixed memory leak in avformat_free_context() (bsc#1237351).
- CVE-2025-0518: Fixed unchecked sscanf return value which leads to memory data leak (bsc#1236007).
- CVE-2025-22919: Fixed denial of service (DoS) via opening a crafted AAC file (bsc#1237371).
- CVE-2024-12361: Fixed NULL Pointer Dereference (bsc#1237358).
- CVE-2024-35368: Fixed Double Free via the rkmpp_retrieve_frame function within libavcodec/rkmppdec.c (bsc#1234028).
- CVE-2024-36613: Fixed Integer overflow in ffmpeg (bsc#1235092).
- CVE-2023-50010: Fixed arbitrary code execution via the set_encoder_id function in /fftools/ffmpeg_enc.c component (bsc#1223256).
- CVE-2023-51794: Fixed heap-buffer-overflow at libavfilter/af_stereowiden.c (bsc#1223437).
- CVE-2023-51793: Fixed heap buffer overflow in the image_copy_plane function in libavutil/imgutils.c (bsc#1223272).
- CVE-2023-49502: Fixed heap buffer overflow via the ff_bwdif_filter_intra_c function in libavfilter/bwdifdsp.c (bsc#1223235).
- CVE-2023-51798: Fixed floating point exception(FPE) via the interpolate function in libavfilter/vf_minterpolate.c (bsc#1223304).
- CVE-2024-31578: Fixed heap use-after-free via the av_hwframe_ctx_init function (bsc#1223070).
- CVE-2024-7055: Fixed heap-based buffer overflow in pnmdec.c (bsc#1229026).
- CVE-2024-32230: Fixed buffer overflow due to negative-size-param bug at libavcodec/mpegvideo_enc.c in load_input_picture (bsc#1227296).

Other fixes:
- Updated to version 4.4.5.");

  script_tag(name:"affected", value:"'ffmpeg-4' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4", rpm:"ffmpeg-4~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavcodec-devel", rpm:"ffmpeg-4-libavcodec-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavdevice-devel", rpm:"ffmpeg-4-libavdevice-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavfilter-devel", rpm:"ffmpeg-4-libavfilter-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavformat-devel", rpm:"ffmpeg-4-libavformat-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavresample-devel", rpm:"ffmpeg-4-libavresample-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavutil-devel", rpm:"ffmpeg-4-libavutil-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libpostproc-devel", rpm:"ffmpeg-4-libpostproc-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswresample-devel", rpm:"ffmpeg-4-libswresample-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswscale-devel", rpm:"ffmpeg-4-libswscale-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-private-devel", rpm:"ffmpeg-4-private-devel~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-32bit", rpm:"libavcodec58_134-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134", rpm:"libavcodec58_134~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-32bit", rpm:"libavdevice58_13-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13", rpm:"libavdevice58_13~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-32bit", rpm:"libavfilter7_110-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110", rpm:"libavfilter7_110~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-32bit", rpm:"libavformat58_76-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76", rpm:"libavformat58_76~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-32bit", rpm:"libavresample4_0-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0", rpm:"libavresample4_0~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-32bit", rpm:"libavutil56_70-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70", rpm:"libavutil56_70~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-32bit", rpm:"libpostproc55_9-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9", rpm:"libpostproc55_9~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-32bit", rpm:"libswresample3_9-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9", rpm:"libswresample3_9~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-32bit", rpm:"libswscale5_9-32bit~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9", rpm:"libswscale5_9~4.4.5~150600.13.16.1", rls:"openSUSELeap15.6"))) {
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
