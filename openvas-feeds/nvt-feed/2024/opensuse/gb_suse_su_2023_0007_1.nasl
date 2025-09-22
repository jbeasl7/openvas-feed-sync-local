# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833730");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-3109");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-20 17:51:52 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:58:17 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for ffmpeg (SUSE-SU-2023:0007-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0007-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DZJP6VU4FHGVMIUOX3YH4GGBNZC36VBG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the SUSE-SU-2023:0007-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:

  - CVE-2022-3109: Fixed null pointer dereference in vp3_decode_frame()
       (bsc#1206442).");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-private-devel", rpm:"ffmpeg-private-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-debuginfo", rpm:"libavdevice57-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-debuginfo", rpm:"libavfilter6-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit", rpm:"libavcodec57-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit-debuginfo", rpm:"libavcodec57-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit", rpm:"libavdevice57-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit-debuginfo", rpm:"libavdevice57-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit", rpm:"libavfilter6-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit-debuginfo", rpm:"libavfilter6-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit", rpm:"libavformat57-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit-debuginfo", rpm:"libavformat57-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit", rpm:"libavresample3-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit-debuginfo", rpm:"libavresample3-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit", rpm:"libavutil55-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit-debuginfo", rpm:"libavutil55-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit", rpm:"libpostproc54-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit-debuginfo", rpm:"libpostproc54-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit", rpm:"libswresample2-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit-debuginfo", rpm:"libswresample2-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit", rpm:"libswscale4-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit-debuginfo", rpm:"libswscale4-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-private-devel", rpm:"ffmpeg-private-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-debuginfo", rpm:"libavdevice57-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-debuginfo", rpm:"libavfilter6-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit", rpm:"libavcodec57-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit-debuginfo", rpm:"libavcodec57-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit", rpm:"libavdevice57-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit-debuginfo", rpm:"libavdevice57-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit", rpm:"libavfilter6-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit-debuginfo", rpm:"libavfilter6-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit", rpm:"libavformat57-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit-debuginfo", rpm:"libavformat57-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit", rpm:"libavresample3-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit-debuginfo", rpm:"libavresample3-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit", rpm:"libavutil55-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit-debuginfo", rpm:"libavutil55-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit", rpm:"libpostproc54-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit-debuginfo", rpm:"libpostproc54-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit", rpm:"libswresample2-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit-debuginfo", rpm:"libswresample2-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit", rpm:"libswscale4-32bit~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit-debuginfo", rpm:"libswscale4-32bit-debuginfo~3.4.2~150200.11.20.1", rls:"openSUSELeap15.4"))) {
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