# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851193");
  script_version("2021-10-07T14:01:22+0000");
  script_tag(name:"last_modification", value:"2021-10-07 14:01:22 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-02-02 17:17:40 +0100 (Tue, 02 Feb 2016)");
  script_cve_id("CVE-2016-1897", "CVE-2016-1898");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for ffmpeg (openSUSE-SU-2016:0243-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to ffmpeg 2.8.5 fixes the following issues:

  * CVE-2016-1897: Cross-origin issue in URL processing (concat) - local
  file disclosure (boo#961937)

  * CVE-2016-1898: Cross-origin issue in URL processing (subfile) - local
  file disclosure (boo#961937)");

  script_tag(name:"affected", value:"ffmpeg on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0243-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-devel", rpm:"ffmpeg-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56", rpm:"libavcodec56~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56-debuginfo", rpm:"libavcodec56-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice56", rpm:"libavdevice56~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice56-debuginfo", rpm:"libavdevice56-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5", rpm:"libavfilter5~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5-debuginfo", rpm:"libavfilter5-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56", rpm:"libavformat56~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56-debuginfo", rpm:"libavformat56-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample2", rpm:"libavresample2~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample2-debuginfo", rpm:"libavresample2-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54", rpm:"libavutil54~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54-debuginfo", rpm:"libavutil54-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53", rpm:"libpostproc53~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53-debuginfo", rpm:"libpostproc53-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1", rpm:"libswresample1~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1-debuginfo", rpm:"libswresample1-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale3", rpm:"libswscale3~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale3-debuginfo", rpm:"libswscale3-debuginfo~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56-32bit", rpm:"libavcodec56-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec56-debuginfo-32bit", rpm:"libavcodec56-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice56-32bit", rpm:"libavdevice56-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice56-debuginfo-32bit", rpm:"libavdevice56-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5-32bit", rpm:"libavfilter5-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter5-debuginfo-32bit", rpm:"libavfilter5-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56-32bit", rpm:"libavformat56-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat56-debuginfo-32bit", rpm:"libavformat56-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample2-32bit", rpm:"libavresample2-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample2-debuginfo-32bit", rpm:"libavresample2-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54-32bit", rpm:"libavutil54-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil54-debuginfo-32bit", rpm:"libavutil54-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53-32bit", rpm:"libpostproc53-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc53-debuginfo-32bit", rpm:"libpostproc53-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1-32bit", rpm:"libswresample1-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample1-debuginfo-32bit", rpm:"libswresample1-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale3-32bit", rpm:"libswscale3-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale3-debuginfo-32bit", rpm:"libswscale3-debuginfo-32bit~2.8.5~12.1", rls:"openSUSELeap42.1"))) {
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
