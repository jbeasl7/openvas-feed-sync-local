# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850298");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:34 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2011-3045", "CVE-2011-3049", "CVE-2011-3050", "CVE-2011-3051",
                "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054", "CVE-2011-3055",
                "CVE-2011-3056");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:0466-1");
  script_name("openSUSE: Security Advisory for update (openSUSE-SU-2012:0466-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.1");

  script_tag(name:"affected", value:"update on openSUSE 12.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"insight", value:"- Update to 19.0.1079 Security Fixes (bnc#754456):

  * High CVE-2011-3050: Use-after-free with first-letter
  handling

  * High CVE-2011-3045: libpng integer issue from upstream

  * High CVE-2011-3051: Use-after-free in CSS cross-fade
  handling

  * High CVE-2011-3052: Memory corruption in WebGL canvas
  handling

  * High CVE-2011-3053: Use-after-free in block splitting

  * Low CVE-2011-3054: Apply additional isolations to
  webui  privileges

  * Low CVE-2011-3055: Prompt in the browser native UI for
  unpacked  extension installation

  * High CVE-2011-3056: Cross-origin violation with 'magic
  iframe'.

  * Low CVE-2011-3049: Extension web request API can
  interfere with system requests Other Fixes:

  * The short-cut key for caps lock (Shift + Search) is
  disabled  when an accessibility screen reader is enabled

  * Fixes an issue with files not being displayed in File
  Manager  when some file names contain UTF-8 characters
  (generally  accented characters)

  * Fixed dialog boxes in settings. (Issue: 118031)

  * Fixed flash videos turning white on mac when running
  with

  - -disable-composited-core-animation-plugins (Issue:
  117916)

  * Change to look for correctly sized favicon when
  multiple images  are provided. (Issue: 118275)

  * Fixed issues - 116044, 117470, 117068, 117668, 118620

  - Update to 19.0.1077

  - Update to 19.0.1074

  - Build Chromium on openSUSE > 12.1 with the gold linker

  - Fix build issues with GCC 4.7

  - Update to 19.0.1071

  * Several fixes and improvements in the new Settings,
  Extensions, and Help pages.

  * Fixed the flashing when switched between composited
  and  non-composited mode. [Issue: 116603]

  * Fixed stability issues 116913, 117217, 117347, 117081");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~19.0.1079.0~1.14.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~19.0.1079.0~1.14.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~19.0.1079.0~1.14.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~19.0.1079.0~1.14.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~19.0.1079.0~1.14.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~19.0.1079.0~1.14.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~19.0.1079.0~1.14.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libv8-3", rpm:"libv8-3~3.9.24.1~1.18.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libv8-3-debuginfo", rpm:"libv8-3-debuginfo~3.9.24.1~1.18.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-debugsource", rpm:"v8-debugsource~3.9.24.1~1.18.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~3.9.24.1~1.18.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-private-headers-devel", rpm:"v8-private-headers-devel~3.9.24.1~1.18.1", rls:"openSUSE12.1"))) {
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
