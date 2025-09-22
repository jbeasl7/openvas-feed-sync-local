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
  script_oid("1.3.6.1.4.1.25623.1.0.851459");
  script_version("2021-10-14T09:01:39+0000");
  script_tag(name:"last_modification", value:"2021-10-14 09:01:39 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-12-17 05:31:26 +0100 (Sat, 17 Dec 2016)");
  script_cve_id("CVE-2016-9080", "CVE-2016-9893", "CVE-2016-9894", "CVE-2016-9895",
                "CVE-2016-9896", "CVE-2016-9897", "CVE-2016-9898", "CVE-2016-9899",
                "CVE-2016-9900", "CVE-2016-9901", "CVE-2016-9902", "CVE-2016-9903",
                "CVE-2016-9904");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 16:52:00 +0000 (Tue, 07 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2016:3184-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to MozillaFirefox 50.1.0 fixes the following vulnerabilities:

  - CVE-2016-9894: Buffer overflow in SkiaGL

  - CVE-2016-9899: Use-after-free while manipulating DOM events and audio
  elements

  - CVE-2016-9895: CSP bypass using marquee tag

  - CVE-2016-9896: Use-after-free with WebVR

  - CVE-2016-9897: Memory corruption in libGLES

  - CVE-2016-9898: Use-after-free in Editor while manipulating DOM subtrees

  - CVE-2016-9900: Restricted external resources can be loaded by SVG images
  through data URLs

  - CVE-2016-9904: Cross-origin information leak in shared atoms

  - CVE-2016-9901: Data from Pocket server improperly sanitized before
  execution

  - CVE-2016-9902: Pocket extension does not validate the origin of events

  - CVE-2016-9903: XSS injection vulnerability in add-ons SDK

  - CVE-2016-9080: Memory safety bugs fixed in Firefox 50.1

  - CVE-2016-9893: Memory safety bugs fixed in Firefox 50.1 and Firefox ESR
  45.6

  The following bugs were fixed:

  - boo#1011922: fix crash after a few seconds of usage on AArch64");

  script_tag(name:"affected", value:"MozillaFirefox on openSUSE Leap 42.1, openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:3184-1");
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~50.1.0~94.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~50.1.0~94.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~50.1.0~94.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~50.1.0~94.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~50.1.0~94.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~50.1.0~94.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~50.1.0~94.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~50.1.0~94.1", rls:"openSUSE13.2"))) {
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
