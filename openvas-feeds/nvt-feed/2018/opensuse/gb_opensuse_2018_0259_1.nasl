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
  script_oid("1.3.6.1.4.1.25623.1.0.851692");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-01-29 07:47:09 +0100 (Mon, 29 Jan 2018)");
  script_cve_id("CVE-2017-15420", "CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033",
                "CVE-2018-6034", "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037",
                "CVE-2018-6038", "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041",
                "CVE-2018-6042", "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046",
                "CVE-2018-6047", "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050",
                "CVE-2018-6051", "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-20 17:34:00 +0000 (Tue, 20 Nov 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2018:0259-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium to 64.0.3282.119 fixes several issues.

  These security issues were fixed:

  - CVE-2018-6031: Use after free in PDFium (boo#1077571)

  - CVE-2018-6032: Same origin bypass in Shared Worker (boo#1077571)

  - CVE-2018-6033: Race when opening downloaded files (boo#1077571)

  - CVE-2018-6034: Integer overflow in Blink (boo#1077571)

  - CVE-2018-6035: Insufficient isolation of devtools from extensions
  (boo#1077571)

  - CVE-2018-6036: Integer underflow in WebAssembly (boo#1077571)

  - CVE-2018-6037: Insufficient user gesture requirements in autofill
  (boo#1077571)

  - CVE-2018-6038: Heap buffer overflow in WebGL (boo#1077571)

  - CVE-2018-6039: XSS in DevTools (boo#1077571)

  - CVE-2018-6040: Content security policy bypass (boo#1077571)

  - CVE-2018-6041: URL spoof in Navigation (boo#1077571)

  - CVE-2018-6042: URL spoof in OmniBox (boo#1077571)

  - CVE-2018-6043: Insufficient escaping with external URL handlers
  (boo#1077571)

  - CVE-2018-6045: Insufficient isolation of devtools from extensions
  (boo#1077571)

  - CVE-2018-6046: Insufficient isolation of devtools from extensions
  (boo#1077571)

  - CVE-2018-6047: Cross origin URL leak in WebGL (boo#1077571)

  - CVE-2018-6048: Referrer policy bypass in Blink (boo#1077571)

  - CVE-2017-15420: URL spoofing in Omnibox (boo#1077571)

  - CVE-2018-6049: UI spoof in Permissions (boo#1077571)

  - CVE-2018-6050: URL spoof in OmniBox (boo#1077571)

  - CVE-2018-6051: Referrer leak in XSS Auditor (boo#1077571)

  - CVE-2018-6052: Incomplete no-referrer policy implementation (boo#1077571)

  - CVE-2018-6053: Leak of page thumbnails in New Tab Page (boo#1077571)

  - CVE-2018-6054: Use after free in WebUI (boo#1077571)

  Re was updated to version 2018-01-01 (boo#1073323)");

  script_tag(name:"affected", value:"chromium on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0259-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-01/msg00079.html");
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
  if(!isnull(res = isrpmvuln(pkg:"libre2-0", rpm:"libre2-0~20180101~9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-debuginfo", rpm:"libre2-0-debuginfo~20180101~9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-debugsource", rpm:"re2-debugsource~20180101~9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-devel", rpm:"re2-devel~20180101~9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~64.0.3282.119~135.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~64.0.3282.119~135.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~64.0.3282.119~135.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~64.0.3282.119~135.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~64.0.3282.119~135.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-32bit", rpm:"libre2-0-32bit~20180101~9.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-0-debuginfo-32bit", rpm:"libre2-0-debuginfo-32bit~20180101~9.1", rls:"openSUSELeap42.3"))) {
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
