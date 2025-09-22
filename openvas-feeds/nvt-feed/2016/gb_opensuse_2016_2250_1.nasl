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
  script_oid("1.3.6.1.4.1.25623.1.0.851389");
  script_version("2021-10-13T10:01:36+0000");
  script_tag(name:"last_modification", value:"2021-10-13 10:01:36 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-09-07 05:43:45 +0200 (Wed, 07 Sep 2016)");
  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150",
                "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154",
                "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158",
                "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162",
                "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2016:2250-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium was updated to 53.0.2785.89 to fix a number of security issues.

  The following vulnerabilities were fixed: (boo#996648)

  - CVE-2016-5147: Universal XSS in Blink.

  - CVE-2016-5148: Universal XSS in Blink.

  - CVE-2016-5149: Script injection in extensions.

  - CVE-2016-5150: Use after free in Blink.

  - CVE-2016-5151: Use after free in PDFium.

  - CVE-2016-5152: Heap overflow in PDFium.

  - CVE-2016-5153: Use after destruction in Blink.

  - CVE-2016-5154: Heap overflow in PDFium.

  - CVE-2016-5155: Address bar spoofing.

  - CVE-2016-5156: Use after free in event bindings.

  - CVE-2016-5157: Heap overflow in PDFium.

  - CVE-2016-5158: Heap overflow in PDFium.

  - CVE-2016-5159: Heap overflow in PDFium.

  - CVE-2016-5161: Type confusion in Blink.

  - CVE-2016-5162: Extensions web accessible resources bypass.

  - CVE-2016-5163: Address bar spoofing.

  - CVE-2016-5164: Universal XSS using DevTools.

  - CVE-2016-5165: Script injection in DevTools.

  - CVE-2016-5166: SMB Relay Attack via Save Page As.

  - CVE-2016-5160: Extensions web accessible resources bypass.

  A number of tracked build system fixes are included. (boo#996032,
  boo#99606, boo#995932)");

  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2250-1");
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
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~53.0.2785.89~68.1", rls:"openSUSELeap42.1"))) {
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
