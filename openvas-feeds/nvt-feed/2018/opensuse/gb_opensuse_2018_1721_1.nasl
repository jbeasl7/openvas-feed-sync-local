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
  script_oid("1.3.6.1.4.1.25623.1.0.851791");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-06-17 05:53:19 +0200 (Sun, 17 Jun 2018)");
  script_cve_id("CVE-2017-1000456", "CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14520",
                "CVE-2017-14617", "CVE-2017-14928", "CVE-2017-14975", "CVE-2017-14976",
                "CVE-2017-14977", "CVE-2017-15565", "CVE-2017-9865");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-30 17:54:00 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for poppler (openSUSE-SU-2018:1721-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

  These security issues were fixed:

  - CVE-2017-14517: Prevent NULL Pointer dereference in the
  XRef::parseEntry() function via a crafted PDF document (bsc#1059066).

  - CVE-2017-9865: Fixed a stack-based buffer overflow vulnerability in
  GfxState.cc that would have allowed attackers to facilitate a
  denial-of-service attack via specially crafted PDF documents.
  (bsc#1045939)

  - CVE-2017-14518: Remedy a floating point exception in
  isImageInterpolationRequired() that could have been exploited using a
  specially crafted PDF document. (bsc#1059101)

  - CVE-2017-14520: Remedy a floating point exception in
  Splash::scaleImageYuXd() that could have been exploited using a
  specially crafted PDF document. (bsc#1059155)

  - CVE-2017-14617: Fixed a floating point exception in Stream.cc, which may
  lead to a potential attack when handling malicious PDF files.
  (bsc#1060220)

  - CVE-2017-14928: Fixed a NULL Pointer dereference in
  AnnotRichMedia::Configuration::Configuration() in Annot.cc, which may
  lead to a potential attack when handling malicious PDF files.
  (bsc#1061092)

  - CVE-2017-14975: Fixed a NULL pointer dereference vulnerability, that
  existed because a data structure in FoFiType1C.cc was not initialized,
  which allowed an attacker to launch a denial of service attack.
  (bsc#1061263)

  - CVE-2017-14976: Fixed a heap-based buffer over-read vulnerability in
  FoFiType1C.cc that occurred when an out-of-bounds font dictionary index
  was encountered, which allowed an attacker to launch a denial of service
  attack. (bsc#1061264)

  - CVE-2017-14977: Fixed a NULL pointer dereference vulnerability in the
  FoFiTrueType::getCFFBlock() function in FoFiTrueType.cc that occurred
  due to lack of validation of a table pointer, which allows an attacker
  to launch a denial of service attack. (bsc#1061265)

  - CVE-2017-15565: Prevent NULL Pointer dereference in the
  GfxImageColorMap::getGrayLine() function via a crafted PDF document
  (bsc#1064593).

  - CVE-2017-1000456: Validate boundaries in TextPool::addWord to prevent
  overflows in subsequent calculations (bsc#1074453).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-648=1");

  script_tag(name:"affected", value:"poppler on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1721-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00032.html");
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
  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo", rpm:"libpoppler-cpp0-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo", rpm:"libpoppler-qt4-4-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1", rpm:"libpoppler-qt5-1~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo", rpm:"libpoppler-qt5-1-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60-debuginfo", rpm:"libpoppler60-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt-debugsource", rpm:"poppler-qt-debugsource~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt5-debugsource", rpm:"poppler-qt5-debugsource~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Poppler-0_18", rpm:"typelib-1_0-Poppler-0_18~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-32bit", rpm:"libpoppler-cpp0-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo-32bit", rpm:"libpoppler-cpp0-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-32bit", rpm:"libpoppler-glib8-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo-32bit", rpm:"libpoppler-glib8-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4-32bit", rpm:"libpoppler-qt4-4-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo-32bit", rpm:"libpoppler-qt4-4-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit", rpm:"libpoppler-qt5-1-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo-32bit", rpm:"libpoppler-qt5-1-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60-32bit", rpm:"libpoppler60-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60-debuginfo-32bit", rpm:"libpoppler60-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3"))) {
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
