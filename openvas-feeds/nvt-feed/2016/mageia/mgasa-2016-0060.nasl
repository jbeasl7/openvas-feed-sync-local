# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131219");
  script_cve_id("CVE-2016-1897", "CVE-2016-1898", "CVE-2016-2213");
  script_tag(name:"creation_date", value:"2016-02-11 05:22:18 +0000 (Thu, 11 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-25 17:40:59 +0000 (Thu, 25 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0060");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0060.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/download.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/security.html");
  script_xref(name:"URL", value:"http://git.videolan.org/?p=ffmpeg.git;a=shortlog;h=n2.4.13");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/02/03/2");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17539");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2016-0060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ffmpeg packages fix security vulnerabilities:

FFmpeg 2.x allows remote attackers to conduct cross-origin attacks and read
arbitrary files by using the concat protocol in an HTTP Live Streaming (HLS)
M3U8 file, leading to an external HTTP request in which the URL string
contains the first line of a local file (CVE-2016-1897).

FFmpeg 2.x allows remote attackers to conduct cross-origin attacks and read
arbitrary files by using the subfile protocol in an HTTP Live Streaming (HLS)
M3U8 file, leading to an external HTTP request in which the URL string
contains an arbitrary line of a local file (CVE-2016-1898).

Out-of-array read in FFmpeg before 2.4.13 in jpeg2000_decode_tile() in
jpeg2000dec.c (CVE-2016-2213).");

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

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec56", rpm:"lib64avcodec56~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec56", rpm:"lib64avcodec56~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter5", rpm:"lib64avfilter5~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter5", rpm:"lib64avfilter5~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat56", rpm:"lib64avformat56~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat56", rpm:"lib64avformat56~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil54", rpm:"lib64avutil54~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil54", rpm:"lib64avutil54~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc53", rpm:"lib64postproc53~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc53", rpm:"lib64postproc53~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample1", rpm:"lib64swresample1~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample1", rpm:"lib64swresample1~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler3", rpm:"lib64swscaler3~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler3", rpm:"lib64swscaler3~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56", rpm:"libavcodec56~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56", rpm:"libavcodec56~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5", rpm:"libavfilter5~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5", rpm:"libavfilter5~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56", rpm:"libavformat56~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56", rpm:"libavformat56~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54", rpm:"libavutil54~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54", rpm:"libavutil54~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53", rpm:"libpostproc53~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53", rpm:"libpostproc53~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1", rpm:"libswresample1~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1", rpm:"libswresample1~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler3", rpm:"libswscaler3~2.4.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler3", rpm:"libswscaler3~2.4.13~1.mga5.tainted", rls:"MAGEIA5"))) {
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
