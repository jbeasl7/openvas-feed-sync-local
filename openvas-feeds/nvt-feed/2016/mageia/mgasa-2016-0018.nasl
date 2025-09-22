# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131185");
  script_cve_id("CVE-2015-6761", "CVE-2015-6818", "CVE-2015-6820", "CVE-2015-6821", "CVE-2015-6822", "CVE-2015-6823", "CVE-2015-6824", "CVE-2015-6825", "CVE-2015-6826", "CVE-2015-8216", "CVE-2015-8219", "CVE-2015-8363", "CVE-2015-8364", "CVE-2015-8365", "CVE-2015-8661", "CVE-2015-8662", "CVE-2015-8663");
  script_tag(name:"creation_date", value:"2016-01-15 06:29:01 +0000 (Fri, 15 Jan 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-24 17:32:05 +0000 (Thu, 24 Dec 2015)");

  script_name("Mageia: Security Advisory (MGASA-2016-0018)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0018");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0018.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/download.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/security.html");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=ffmpeg.git;a=shortlog;h=n2.4.12");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17257");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2016-0018 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The update_dimensions function in libavcodec/vp8.c in FFmpeg before 2.4.12,
as used in Google Chrome before 46.0.2490.71 and other products, relies on a
coefficient-partition count during multi-threaded operation, which allows
remote attackers to cause a denial of service (race condition and memory
corruption) or possibly have unspecified other impact via a crafted WebM file
(CVE-2015-6761).

The decode_ihdr_chunk function in libavcodec/pngdec.c in FFmpeg before 2.4.11
does not enforce uniqueness of the IHDR (aka image header) chunk in a PNG
image, which allows remote attackers to cause a denial of service
(out-of-bounds array access) or possibly have unspecified other impact via a
crafted image with two or more of these chunks (CVE-2015-6818).

The ff_sbr_apply function in libavcodec/aacsbr.c in FFmpeg before 2.4.11 does
not check for a matching AAC frame syntax element before proceeding with
Spectral Band Replication calculations, which allows remote attackers to
cause a denial of service (out-of-bounds array access) or possibly have
unspecified other impact via crafted AAC data (CVE-2015-6820).

The ff_mpv_common_init function in libavcodec/mpegvideo.c in FFmpeg before
2.4.11 does not properly maintain the encoding context, which allows remote
attackers to cause a denial of service (invalid pointer access) or possibly
have unspecified other impact via crafted MPEG data (CVE-2015-6821).

The destroy_buffers function in libavcodec/sanm.c in FFmpeg before 2.4.11
does not properly maintain height and width values in the video context,
which allows remote attackers to cause a denial of service (segmentation
violation and application crash) or possibly have unspecified other impact
via crafted LucasArts Smush video data (CVE-2015-6822).

The allocate_buffers function in libavcodec/alac.c in FFmpeg before 2.4.11
does not initialize certain context data, which allows remote attackers to
cause a denial of service (segmentation violation) or possibly have
unspecified other impact via crafted Apple Lossless Audio Codec (ALAC) data
(CVE-2015-6823).

The sws_init_context function in libswscale/utils.c in FFmpeg before 2.4.11
does not initialize certain pixbuf data structures, which allows remote
attackers to cause a denial of service (segmentation violation) or possibly
have unspecified other impact via crafted video data (CVE-2015-6824).

The ff_frame_thread_init function in libavcodec/pthread_frame.c in FFmpeg
before 2.4.11 mishandles certain memory-allocation failures, which allows
remote attackers to cause a denial of service (invalid pointer access) or
possibly have unspecified other impact via a crafted file, as demonstrated
by an AVI file (CVE-2015-6825).

The ff_rv34_decode_init_thread_copy function in libavcodec/rv34.c in FFmpeg
before 2.4.11 does not initialize certain structure members, which allows
remote attackers to cause a denial of service (invalid pointer access) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec56", rpm:"lib64avcodec56~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec56", rpm:"lib64avcodec56~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter5", rpm:"lib64avfilter5~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter5", rpm:"lib64avfilter5~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat56", rpm:"lib64avformat56~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat56", rpm:"lib64avformat56~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil54", rpm:"lib64avutil54~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil54", rpm:"lib64avutil54~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc53", rpm:"lib64postproc53~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc53", rpm:"lib64postproc53~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample1", rpm:"lib64swresample1~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample1", rpm:"lib64swresample1~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler3", rpm:"lib64swscaler3~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler3", rpm:"lib64swscaler3~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56", rpm:"libavcodec56~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56", rpm:"libavcodec56~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5", rpm:"libavfilter5~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5", rpm:"libavfilter5~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56", rpm:"libavformat56~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56", rpm:"libavformat56~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54", rpm:"libavutil54~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54", rpm:"libavutil54~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53", rpm:"libpostproc53~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53", rpm:"libpostproc53~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1", rpm:"libswresample1~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1", rpm:"libswresample1~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler3", rpm:"libswscaler3~2.4.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler3", rpm:"libswscaler3~2.4.12~1.mga5.tainted", rls:"MAGEIA5"))) {
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
