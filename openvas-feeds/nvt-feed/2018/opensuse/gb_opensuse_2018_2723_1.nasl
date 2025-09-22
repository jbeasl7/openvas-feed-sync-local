# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851894");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-09-16 07:52:45 +0200 (Sun, 16 Sep 2018)");
  script_cve_id("CVE-2018-13300", "CVE-2018-15822");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 18:15:00 +0000 (Mon, 04 Jan 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for ffmpeg-4 (openSUSE-SU-2018:2723-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg-4'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 to version 4.0.2 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-15822: The flv_write_packet function did not check for an empty
  audio packet, leading to an assertion failure and DoS (bsc#1105869).

  - CVE-2018-13300: An improper argument passed to the avpriv_request_sample
  function may have triggered an out-of-array read while converting a
  crafted AVI file to MPEG4, leading to a denial of service and possibly
  an information disclosure (bsc#1100348).

  These non-security issues were fixed:

  - Enable webvtt encoders and decoders (boo#1092241).

  - Build codec2 encoder and decoder, add libcodec2 to enable_decoders and
  enable_encoders.

  - Enable mpeg 1 and 2 encoders.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1004=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1004=1");

  script_tag(name:"affected", value:"ffmpeg-4 on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2723-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00025.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debugsource", rpm:"ffmpeg-4-debugsource~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavcodec-devel", rpm:"ffmpeg-4-libavcodec-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavdevice-devel", rpm:"ffmpeg-4-libavdevice-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavfilter-devel", rpm:"ffmpeg-4-libavfilter-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavformat-devel", rpm:"ffmpeg-4-libavformat-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavresample-devel", rpm:"ffmpeg-4-libavresample-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavutil-devel", rpm:"ffmpeg-4-libavutil-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libpostproc-devel", rpm:"ffmpeg-4-libpostproc-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswresample-devel", rpm:"ffmpeg-4-libswresample-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswscale-devel", rpm:"ffmpeg-4-libswscale-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-private-devel", rpm:"ffmpeg-4-private-devel~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58", rpm:"libavcodec58~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58-debuginfo", rpm:"libavcodec58-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58", rpm:"libavdevice58~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58-debuginfo", rpm:"libavdevice58-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7", rpm:"libavfilter7~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7-debuginfo", rpm:"libavfilter7-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58", rpm:"libavformat58~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58-debuginfo", rpm:"libavformat58-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4", rpm:"libavresample4~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4-debuginfo", rpm:"libavresample4-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56", rpm:"libavutil56~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56-debuginfo", rpm:"libavutil56-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55", rpm:"libpostproc55~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55-debuginfo", rpm:"libpostproc55-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3", rpm:"libswresample3~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3-debuginfo", rpm:"libswresample3-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5", rpm:"libswscale5~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5-debuginfo", rpm:"libswscale5-debuginfo~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58-32bit", rpm:"libavcodec58-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58-debuginfo-32bit", rpm:"libavcodec58-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58-32bit", rpm:"libavdevice58-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58-debuginfo-32bit", rpm:"libavdevice58-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7-32bit", rpm:"libavfilter7-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7-debuginfo-32bit", rpm:"libavfilter7-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58-32bit", rpm:"libavformat58-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58-debuginfo-32bit", rpm:"libavformat58-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4-32bit", rpm:"libavresample4-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4-debuginfo-32bit", rpm:"libavresample4-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56-32bit", rpm:"libavutil56-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56-debuginfo-32bit", rpm:"libavutil56-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55-32bit", rpm:"libpostproc55-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55-debuginfo-32bit", rpm:"libpostproc55-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3-32bit", rpm:"libswresample3-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3-debuginfo-32bit", rpm:"libswresample3-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5-32bit", rpm:"libswscale5-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5-debuginfo-32bit", rpm:"libswscale5-debuginfo-32bit~4.0.2~13.1", rls:"openSUSELeap42.3"))) {
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
