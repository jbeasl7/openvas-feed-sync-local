# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0245");
  script_cve_id("CVE-2014-9316", "CVE-2014-9317", "CVE-2014-9318", "CVE-2014-9603", "CVE-2014-9604", "CVE-2015-1872", "CVE-2015-3395", "CVE-2015-3417");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0245)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0245");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0245.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/olddownload.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/security.html");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=ffmpeg.git;a=log;h=n2.0.7");
  script_xref(name:"URL", value:"http://vigilance.fr/vulnerability/FFmpeg-unreachable-memory-reading-via-mjpegdec-c-16213");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15502");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2015-0245 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The mjpeg_decode_app function in libavcodec/mjpegdec.c in FFMpeg before 2.0.7
allows remote attackers to cause a denial of service (out-of-bounds heap
access) and possibly have other unspecified impact via vectors related to
LJIF tags in an MJPEG file (CVE-2014-9316).

The decode_ihdr_chunk function in libavcodec/pngdec.c in FFMpeg before 2.0.7
allows remote attackers to cause a denial of service (out-of-bounds heap
access) and possibly have other unspecified impact via an IDAT before an IHDR
in a PNG file (CVE-2014-9317).

The raw_decode function in libavcodec/rawdec.c in FFMpeg before 2.0.7 allows
remote attackers to cause a denial of service (out-of-bounds heap access) and
possibly have other unspecified impact via a crafted .cine file that triggers
the avpicture_get_size function to return a negative frame size
(CVE-2014-9318).

The vmd_decode function in libavcodec/vmdvideo.c in FFmpeg before 2.0.7 does
not validate the relationship between a certain length value and the frame
width, which allows remote attackers to cause a denial of service
(out-of-bounds array access) or possibly have unspecified other impact via
crafted Sierra VMD video data (CVE-2014-9603).

libavcodec/utvideodec.c in FFmpeg before 2.0.7 does not check for a zero
value of a slice height, which allows remote attackers to cause a denial of
service (out-of-bounds array access) or possibly have unspecified other
impact via crafted Ut Video data, related to the restore_median and
restore_median_il functions (CVE-2014-9604).

An attacker can force a read at an invalid address in mjpegdec.c of FFmpeg,
in order to trigger a denial of service (CVE-2015-1872).

The msrle_decode_pal4 function in libavcodec/msrledec.c in FFmpeg before
2.0.7 has an out-of-bounds array access that may allow remote attackers to
cause a denial of service or possibly have unspecified other impact via a
crafted BMP file (CVE-2015-3395).

Use-after-free vulnerability in the ff_h264_free_tables function in
libavcodec/h264.c in FFmpeg before 2.0.7 allows remote attackers to cause a
denial of service or possibly have unspecified other impact via crafted H.264
data in an MP4 file, as demonstrated by an HTML VIDEO element that references
H.264 data (CVE-2015-3417).");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec55", rpm:"lib64avcodec55~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec55", rpm:"lib64avcodec55~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter3", rpm:"lib64avfilter3~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter3", rpm:"lib64avfilter3~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat55", rpm:"lib64avformat55~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat55", rpm:"lib64avformat55~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil52", rpm:"lib64avutil52~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil52", rpm:"lib64avutil52~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc52", rpm:"lib64postproc52~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc52", rpm:"lib64postproc52~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample0", rpm:"lib64swresample0~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample0", rpm:"lib64swresample0~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler2", rpm:"lib64swscaler2~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler2", rpm:"lib64swscaler2~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec55", rpm:"libavcodec55~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec55", rpm:"libavcodec55~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter3", rpm:"libavfilter3~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter3", rpm:"libavfilter3~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat55", rpm:"libavformat55~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat55", rpm:"libavformat55~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil52", rpm:"libavutil52~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil52", rpm:"libavutil52~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc52", rpm:"libpostproc52~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc52", rpm:"libpostproc52~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample0", rpm:"libswresample0~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample0", rpm:"libswresample0~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler2", rpm:"libswscaler2~2.0.7~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler2", rpm:"libswscaler2~2.0.7~1.mga4.tainted", rls:"MAGEIA4"))) {
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
