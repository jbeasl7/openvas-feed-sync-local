# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850665");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2015-1270", "CVE-2015-1271", "CVE-2015-1272", "CVE-2015-1273",
                "CVE-2015-1274", "CVE-2015-1275", "CVE-2015-1276", "CVE-2015-1277",
                "CVE-2015-1278", "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281",
                "CVE-2015-1282", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285",
                "CVE-2015-1286", "CVE-2015-1287", "CVE-2015-1288", "CVE-2015-1289",
                "CVE-2015-5605");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2015-08-11 11:55:23 +0530 (Tue, 11 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2015:1287-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium was updated to 44.0.2403.89 to fix multiple security issues.

  The following vulnerabilities were fixed:

  * CVE-2015-1271: Heap-buffer-overflow in pdfium

  * CVE-2015-1273: Heap-buffer-overflow in pdfium

  * CVE-2015-1274: Settings allowed executable files to run immediately
  after download

  * CVE-2015-1275: UXSS in Chrome for Android

  * CVE-2015-1276: Use-after-free in IndexedDB

  * CVE-2015-1279: Heap-buffer-overflow in pdfium

  * CVE-2015-1280: Memory corruption in skia

  * CVE-2015-1281: CSP bypass

  * CVE-2015-1282: Use-after-free in pdfium

  * CVE-2015-1283: Heap-buffer-overflow in expat

  * CVE-2015-1284: Use-after-free in blink

  * CVE-2015-1286: UXSS in blink

  * CVE-2015-1287: SOP bypass with CSS

  * CVE-2015-1270: Uninitialized memory read in ICU

  * CVE-2015-1272: Use-after-free related to unexpected GPU process
  termination

  * CVE-2015-1277: Use-after-free in accessibility

  * CVE-2015-1278: URL spoofing using pdf files

  * CVE-2015-1285: Information leak in XSS auditor

  * CVE-2015-1288: Spell checking dictionaries fetched over HTTP

  * CVE-2015-1289: Various fixes from internal audits, fuzzing and other
  initiatives

  * CVE-2015-5605: Rgular-expression implementation mishandles interrupts,
  DoS via JS

  The following non-security changes are included:

  * A number of new apps/extension APIs

  * Lots of under the hood changes for stability and performance

  * Pepper Flash plugin updated to 18.0.0.209");

  script_tag(name:"affected", value:"Chromium on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:1287-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~44.0.2403.89~93.1", rls:"openSUSE13.1"))) {
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
