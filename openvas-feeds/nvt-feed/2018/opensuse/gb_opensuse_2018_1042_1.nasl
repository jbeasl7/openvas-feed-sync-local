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
  script_oid("1.3.6.1.4.1.25623.1.0.851732");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-04-21 08:59:09 +0200 (Sat, 21 Apr 2018)");
  script_cve_id("CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088",
                "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092",
                "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096",
                "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100",
                "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104",
                "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108",
                "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112",
                "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6115", "CVE-2018-6116",
                "CVE-2018-6117");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 20:03:00 +0000 (Fri, 01 Mar 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2018:1042-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Chromium to version 66.0.3359.117 fixes the following
  issues:

  Security issues fixed (boo#1090000):

  - CVE-2018-6085: Use after free in Disk Cache

  - CVE-2018-6086: Use after free in Disk Cache

  - CVE-2018-6087: Use after free in WebAssembly

  - CVE-2018-6088: Use after free in PDFium

  - CVE-2018-6089: Same origin policy bypass in Service Worker

  - CVE-2018-6090: Heap buffer overflow in Skia

  - CVE-2018-6091: Incorrect handling of plug-ins by Service Worker

  - CVE-2018-6092: Integer overflow in WebAssembly

  - CVE-2018-6093: Same origin bypass in Service Worker

  - CVE-2018-6094: Exploit hardening regression in Oilpan

  - CVE-2018-6095: Lack of meaningful user interaction requirement before
  file upload

  - CVE-2018-6096: Fullscreen UI spoof

  - CVE-2018-6097: Fullscreen UI spoof

  - CVE-2018-6098: URL spoof in Omnibox

  - CVE-2018-6099: CORS bypass in ServiceWorker

  - CVE-2018-6100: URL spoof in Omnibox

  - CVE-2018-6101: Insufficient protection of remote debugging prototol in
  DevTools

  - CVE-2018-6102: URL spoof in Omnibox

  - CVE-2018-6103: UI spoof in Permissions

  - CVE-2018-6104: URL spoof in Omnibox

  - CVE-2018-6105: URL spoof in Omnibox

  - CVE-2018-6106: Incorrect handling of promises in V8

  - CVE-2018-6107: URL spoof in Omnibox

  - CVE-2018-6108: URL spoof in Omnibox

  - CVE-2018-6109: Incorrect handling of files by FileAPI

  - CVE-2018-6110: Incorrect handling of plaintext files via file://

  - CVE-2018-6111: Heap-use-after-free in DevTools

  - CVE-2018-6112: Incorrect URL handling in DevTools

  - CVE-2018-6113: URL spoof in Navigation

  - CVE-2018-6114: CSP bypass

  - CVE-2018-6115: SmartScreen bypass in downloads

  - CVE-2018-6116: Incorrect low memory handling in WebAssembly

  - CVE-2018-6117: Confusing autofill settings

  - Various fixes from internal audits, fuzzing and other initiatives

  This update also supports mitigation against the Spectre vulnerabilities:
  'Strict site isolation' is disabled for most users and can be turned on
  via: chrome://flags/#enable-site-per-process This feature is undergoing a
  small percentage trial. Out out of the trial is possible via:
  chrome://flags/#site-isolation-trial-opt-out

  The following other changes are included:

  - distrust certificates issued by Symantec before 2016-06-01

  - add option to export saved passwords

  - Reduce videos that auto-play with sound

  - boo#1086199: Fix UI freezing when loading/scaling down large images

  This update also contains a number of upstream bug fixes and improvements.

  Patch Instructions:

  To install this openSUSE Security Update use the S ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1042-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-04/msg00063.html");
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
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~66.0.3359.117~152.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~66.0.3359.117~152.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~66.0.3359.117~152.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~66.0.3359.117~152.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~66.0.3359.117~152.1", rls:"openSUSELeap42.3"))) {
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
