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
  script_oid("1.3.6.1.4.1.25623.1.0.851325");
  script_version("2021-09-20T14:01:48+0000");
  script_tag(name:"last_modification", value:"2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-06-06 05:25:42 +0200 (Mon, 06 Jun 2016)");
  script_cve_id("CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675",
                "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679",
                "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683",
                "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687",
                "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691",
                "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695",
                "CVE-2016-1696", "CVE-2016-1697", "CVE-2016-1698", "CVE-2016-1699",
                "CVE-2016-1700", "CVE-2016-1701", "CVE-2016-1702", "CVE-2016-1703");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2016:1496-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium was updated to 51.0.2704.79 to fix the following vulnerabilities:

  - CVE-2016-1696: Cross-origin bypass in Extension bindings

  - CVE-2016-1697: Cross-origin bypass in Blink

  - CVE-2016-1698: Information leak in Extension bindings

  - CVE-2016-1699: Parameter sanitization failure in DevTools

  - CVE-2016-1700: Use-after-free in Extensions

  - CVE-2016-1701: Use-after-free in Autofill

  - CVE-2016-1702: Out-of-bounds read in Skia

  - CVE-2016-1703: Various fixes from internal audits, fuzzing and other
  initiatives

  Also includes vulnerabilities fixed in 51.0.2704.63 (boo#981886):

  - CVE-2016-1672: Cross-origin bypass in extension bindings

  - CVE-2016-1673: Cross-origin bypass in Blink

  - CVE-2016-1674: Cross-origin bypass in extensions

  - CVE-2016-1675: Cross-origin bypass in Blink

  - CVE-2016-1676: Cross-origin bypass in extension bindings

  - CVE-2016-1677: Type confusion in V8

  - CVE-2016-1678: Heap overflow in V8

  - CVE-2016-1679: Heap use-after-free in V8 bindings

  - CVE-2016-1680: Heap use-after-free in Skia

  - CVE-2016-1681: Heap overflow in PDFium

  - CVE-2016-1682: CSP bypass for ServiceWorker

  - CVE-2016-1683: Out-of-bounds access in libxslt

  - CVE-2016-1684: Integer overflow in libxslt

  - CVE-2016-1685: Out-of-bounds read in PDFium

  - CVE-2016-1686: Out-of-bounds read in PDFium

  - CVE-2016-1687: Information leak in extensions

  - CVE-2016-1688: Out-of-bounds read in V8

  - CVE-2016-1689: Heap buffer overflow in media

  - CVE-2016-1690: Heap use-after-free in Autofill

  - CVE-2016-1691: Heap buffer-overflow in Skia

  - CVE-2016-1692: Limited cross-origin bypass in ServiceWorker

  - CVE-2016-1693: HTTP Download of Software Removal Tool

  - CVE-2016-1694: HPKP pins removed on cache clearance

  - CVE-2016-1695: Various fixes from internal audits, fuzzing and other
  initiatives");

  script_tag(name:"affected", value:"Chromium on openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:1496-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~51.0.2704.79~105.2", rls:"openSUSE13.2"))) {
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
