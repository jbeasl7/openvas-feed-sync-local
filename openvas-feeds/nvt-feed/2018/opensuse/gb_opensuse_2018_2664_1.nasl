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
  script_oid("1.3.6.1.4.1.25623.1.0.851883");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-09-09 07:06:26 +0200 (Sun, 09 Sep 2018)");
  script_cve_id("CVE-2017-15430", "CVE-2018-16065", "CVE-2018-16066", "CVE-2018-16067",
                "CVE-2018-16068", "CVE-2018-16069", "CVE-2018-16070", "CVE-2018-16071",
                "CVE-2018-16073", "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076",
                "CVE-2018-16077", "CVE-2018-16078", "CVE-2018-16079", "CVE-2018-16080",
                "CVE-2018-16081", "CVE-2018-16082", "CVE-2018-16083", "CVE-2018-16084",
                "CVE-2018-16085", "CVE-2018-16086", "CVE-2018-16087", "CVE-2018-16088");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2018:2664-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Chromium to version 69.0.3497.81 fixes multiple issues.

  Security issues fixed (boo#1107235):

  - CVE-2018-16065: Out of bounds write in V8

  - CVE-2018-16066:Out of bounds read in Blink

  - CVE-2018-16067: Out of bounds read in WebAudio

  - CVE-2018-16068: Out of bounds write in Mojo

  - CVE-2018-16069:Out of bounds read in SwiftShader

  - CVE-2018-16070: Integer overflow in Skia

  - CVE-2018-16071: Use after free in WebRTC

  - CVE-2018-16073: Site Isolation bypass after tab restore

  - CVE-2018-16074: Site Isolation bypass using Blob URLS

  - Out of bounds read in Little-CMS

  - CVE-2018-16075: Local file access in Blink

  - CVE-2018-16076: Out of bounds read in PDFium

  - CVE-2018-16077: Content security policy bypass in Blink

  - CVE-2018-16078: Credit card information leak in Autofill

  - CVE-2018-16079: URL spoof in permission dialogs

  - CVE-2018-16080: URL spoof in full screen mode

  - CVE-2018-16081: Local file access in DevTools

  - CVE-2018-16082: Stack buffer overflow in SwiftShader

  - CVE-2018-16083: Out of bounds read in WebRTC

  - CVE-2018-16084: User confirmation bypass in external protocol handling

  - CVE-2018-16085: Use after free in Memory Instrumentation

  - CVE-2017-15430: Unsafe navigation in Chromecast (boo#1106341)

  - CVE-2018-16086: Script injection in New Tab Page

  - CVE-2018-16087: Multiple download restriction bypass

  - CVE-2018-16088: User gesture requirement bypass

  The re2 regular expression library was updated to the current version
  2018-09-01.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-979=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-979=1");

  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2664-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00017.html");
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
  if(!isnull(res = isrpmvuln(pkg:"libre2-0", rpm:"libre2-0~20180901~18.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-debuginfo", rpm:"libre2-0-debuginfo~20180901~18.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-debugsource", rpm:"re2-debugsource~20180901~18.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-devel", rpm:"re2-devel~20180901~18.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~69.0.3497.81~168.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~69.0.3497.81~168.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~69.0.3497.81~168.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~69.0.3497.81~168.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~69.0.3497.81~168.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-32bit", rpm:"libre2-0-32bit~20180901~18.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-debuginfo-32bit", rpm:"libre2-0-debuginfo-32bit~20180901~18.1", rls:"openSUSELeap42.3"))) {
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
