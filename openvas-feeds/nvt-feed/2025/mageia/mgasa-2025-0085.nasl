# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0085");
  script_cve_id("CVE-2025-0518", "CVE-2025-22919", "CVE-2025-22920", "CVE-2025-22921", "CVE-2025-25473");
  script_tag(name:"creation_date", value:"2025-03-03 04:09:02 +0000 (Mon, 03 Mar 2025)");
  script_version("2025-08-06T05:45:41+0000");
  script_tag(name:"last_modification", value:"2025-08-06 05:45:41 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-05 19:54:45 +0000 (Tue, 05 Aug 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0085)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0085");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0085.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34054");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/G5BFJ3U3RQS5BEVWWNUO24FHCSLCALHX/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2025-0085 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A reachable assertion in FFmpeg git-master commit N-113007-g8d24a28d06
allows attackers to cause a Denial of Service (DoS) via opening a
crafted AAC file. (CVE-2025-22919)
A heap buffer overflow vulnerability in FFmpeg before commit 4bf784c
allows attackers to trigger a memory corruption via supplying a crafted
media file in avformat when processing tile grid group streams. This can
lead to a Denial of Service (DoS). (CVE-2025-22920)
FFmpeg git-master,N-113007-g8d24a28d06 was discovered to contain a
segmentation violation via the component /libavcodec/jpeg2000dec.c.
(CVE-2025-22921)
FFmpeg git master before commit c08d30 was discovered to contain a NULL
pointer dereference via the component libavformat/mov.c.
(CVE-2025-25473)");

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

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec59", rpm:"lib64avcodec59~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec59", rpm:"lib64avcodec59~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter8", rpm:"lib64avfilter8~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter8", rpm:"lib64avfilter8~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat59", rpm:"lib64avformat59~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat59", rpm:"lib64avformat59~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil57", rpm:"lib64avutil57~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil57", rpm:"lib64avutil57~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc56", rpm:"lib64postproc56~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc56", rpm:"lib64postproc56~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample4", rpm:"lib64swresample4~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample4", rpm:"lib64swresample4~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler6", rpm:"lib64swscaler6~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler6", rpm:"lib64swscaler6~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec59", rpm:"libavcodec59~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec59", rpm:"libavcodec59~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter8", rpm:"libavfilter8~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter8", rpm:"libavfilter8~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat59", rpm:"libavformat59~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat59", rpm:"libavformat59~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil57", rpm:"libavutil57~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil57", rpm:"libavutil57~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc56", rpm:"libpostproc56~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc56", rpm:"libpostproc56~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample4", rpm:"libswresample4~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample4", rpm:"libswresample4~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler6", rpm:"libswscaler6~5.1.6~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler6", rpm:"libswscaler6~5.1.6~1.3.mga9.tainted", rls:"MAGEIA9"))) {
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
