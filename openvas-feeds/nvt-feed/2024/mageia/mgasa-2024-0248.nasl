# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0248");
  script_cve_id("CVE-2023-50010", "CVE-2023-51793", "CVE-2023-51794", "CVE-2023-51795", "CVE-2023-51798", "CVE-2024-31585");
  script_tag(name:"creation_date", value:"2024-07-02 04:11:44 +0000 (Tue, 02 Jul 2024)");
  script_version("2024-07-02T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-02 05:05:43 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0248");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0248.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33338");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2024/msg00122.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2024-0248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer Overflow vulnerability in Ffmpeg v.n6.1-3-g466799d4f5 allows a
local attacker to execute arbitrary code via the set_encoder_id function
in /fftools/ffmpeg_enc.c component. (CVE-2023-50010)
Buffer Overflow vulnerability in Ffmpeg v.N113007-g8d24a28d06 allows a
local attacker to execute arbitrary code via the
libavutil/imgutils.c:353:9 in image_copy_plane. (CVE-2023-51793)
Buffer Overflow vulnerability in Ffmpeg v.N113007-g8d24a28d06 allows a
local attacker to execute arbitrary code via the
libavfilter/af_stereowiden.c:120:69. (CVE-2023-51794)
Buffer Overflow vulnerability in Ffmpeg v.N113007-g8d24a28d06 allows a
local attacker to execute arbitrary code via the
libavfilter/avf_showspectrum.c:1789:52 component in
showspectrumpic_request_frame. (CVE-2023-51795)
Buffer Overflow vulnerability in Ffmpeg v.N113007-g8d24a28d06 allows a
local attacker to execute arbitrary code via a floating point exception
(FPE) error at libavfilter/vf_minterpolate.c:1078:60 in interpolate.
(CVE-2023-51798)
FFmpeg version n5.1 to n6.1 was discovered to contain an Off-by-one
Error vulnerability in libavfilter/avf_showspectrum.c. This
vulnerability allows attackers to cause a Denial of Service (DoS) via a
crafted input. (CVE-2024-31585)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec59", rpm:"lib64avcodec59~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec59", rpm:"lib64avcodec59~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter8", rpm:"lib64avfilter8~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter8", rpm:"lib64avfilter8~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat59", rpm:"lib64avformat59~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat59", rpm:"lib64avformat59~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil57", rpm:"lib64avutil57~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil57", rpm:"lib64avutil57~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc56", rpm:"lib64postproc56~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc56", rpm:"lib64postproc56~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample4", rpm:"lib64swresample4~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample4", rpm:"lib64swresample4~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler6", rpm:"lib64swscaler6~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler6", rpm:"lib64swscaler6~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec59", rpm:"libavcodec59~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec59", rpm:"libavcodec59~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter8", rpm:"libavfilter8~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter8", rpm:"libavfilter8~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat59", rpm:"libavformat59~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat59", rpm:"libavformat59~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil57", rpm:"libavutil57~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil57", rpm:"libavutil57~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc56", rpm:"libpostproc56~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc56", rpm:"libpostproc56~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample4", rpm:"libswresample4~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample4", rpm:"libswresample4~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler6", rpm:"libswscaler6~5.1.5~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler6", rpm:"libswscaler6~5.1.5~1.mga9.tainted", rls:"MAGEIA9"))) {
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
