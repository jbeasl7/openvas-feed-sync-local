# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856420");
  script_cve_id("CVE-2020-22027", "CVE-2021-38291", "CVE-2023-51798");
  script_tag(name:"creation_date", value:"2024-09-06 04:00:35 +0000 (Fri, 06 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 19:54:22 +0000 (Wed, 02 Jun 2021)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3114-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243114-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223304");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036758.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the SUSE-SU-2024:3114-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:

- CVE-2020-22027: Fixed heap-based Buffer Overflow vulnerability exits in deflate16 at libavfilter/vf_neighbor.c (bsc#1186607)
- CVE-2021-38291: Fixed an assertion failure at src/libavutil/mathematics.c (bsc#1189428)
- CVE-2023-51798: Fixed floating point exception(FPE) via the interpolate function (bsc#1223304)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-private-devel", rpm:"ffmpeg-private-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit", rpm:"libavcodec57-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit", rpm:"libavdevice57-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit", rpm:"libavfilter6-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit", rpm:"libavformat57-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit", rpm:"libavresample3-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit", rpm:"libavutil55-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit", rpm:"libpostproc54-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit", rpm:"libswresample2-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit", rpm:"libswscale4-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-private-devel", rpm:"ffmpeg-private-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit", rpm:"libavcodec57-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit", rpm:"libavdevice57-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit", rpm:"libavfilter6-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit", rpm:"libavformat57-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit", rpm:"libavresample3-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit", rpm:"libavutil55-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit", rpm:"libpostproc54-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit", rpm:"libswresample2-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit", rpm:"libswscale4-32bit~3.4.2~150200.11.57.1", rls:"openSUSELeap15.6"))) {
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
