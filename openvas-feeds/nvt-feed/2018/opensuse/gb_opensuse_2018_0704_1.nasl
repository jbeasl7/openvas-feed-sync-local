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
  script_oid("1.3.6.1.4.1.25623.1.0.851718");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-03-17 08:45:38 +0100 (Sat, 17 Mar 2018)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-11215", "CVE-2017-11225", "CVE-2018-6057", "CVE-2018-6060",
                "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063", "CVE-2018-6064",
                "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067", "CVE-2018-6068",
                "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072",
                "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076",
                "CVE-2018-6077", "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080",
                "CVE-2018-6081", "CVE-2018-6082", "CVE-2018-6083");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-21 15:28:00 +0000 (Thu, 21 Dec 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2018:0704-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Chromium to version 65.0.3325.162 fixes the following
  issues:

  - CVE-2017-11215: Use after free in Flash

  - CVE-2017-11225: Use after free in Flash

  - CVE-2018-6060: Use after free in Blink

  - CVE-2018-6061: Race condition in V8

  - CVE-2018-6062: Heap buffer overflow in Skia

  - CVE-2018-6057: Incorrect permissions on shared memory

  - CVE-2018-6063: Incorrect permissions on shared memory

  - CVE-2018-6064: Type confusion in V8

  - CVE-2018-6065: Integer overflow in V8

  - CVE-2018-6066: Same Origin Bypass via canvas

  - CVE-2018-6067: Buffer overflow in Skia

  - CVE-2018-6068: Object lifecycle issues in Chrome Custom Tab

  - CVE-2018-6069: Stack buffer overflow in Skia

  - CVE-2018-6070: CSP bypass through extensions

  - CVE-2018-6071: Heap buffer overflow in Skia

  - CVE-2018-6072: Integer overflow in PDFium

  - CVE-2018-6073: Heap buffer overflow in WebGL

  - CVE-2018-6074: Mark-of-the-Web bypass

  - CVE-2018-6075: Overly permissive cross origin downloads

  - CVE-2018-6076: Incorrect handling of URL fragment identifiers in Blink

  - CVE-2018-6077: Timing attack using SVG filters

  - CVE-2018-6078: URL Spoof in OmniBox

  - CVE-2018-6079: Information disclosure via texture data in WebGL

  - CVE-2018-6080: Information disclosure in IPC call

  - CVE-2018-6081: XSS in interstitials

  - CVE-2018-6082: Circumvention of port blocking

  - CVE-2018-6083: Incorrect processing of AppManifests");

  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0704-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-03/msg00042.html");
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
  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~65.0.3325.162~146.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~65.0.3325.162~146.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~65.0.3325.162~146.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~65.0.3325.162~146.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~65.0.3325.162~146.1", rls:"openSUSELeap42.3"))) {
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
