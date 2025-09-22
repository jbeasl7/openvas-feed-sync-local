# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850169");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"SUSE-SA", value:"2011-028");
  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2366", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2369", "CVE-2011-2370", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2376", "CVE-2011-2377");
  script_name("SUSE: Security Advisory for MozillaFirefox, MozillaThunderbird (SUSE-SA:2011:028)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaThunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE11\.3)");

  script_tag(name:"impact", value:"remote code execution");

  script_tag(name:"affected", value:"MozillaFirefox, MozillaThunderbird on openSUSE 11.3, openSUSE 11.4");

  script_tag(name:"insight", value:"Mozilla Firefox and Thunderbird were updated to fix several security issues:

  * CVE-2011-2365
  Miscellaneous memory safety hazards

  * CVE-2011-2373
  Use-after-free vulnerability when viewing XUL document with
  script disabled

  * CVE-2011-2377
  Memory corruption due to multipart/x-mixed-replace images

  * CVE-2011-2371
  Integer overflow and arbitrary code execution in
  Array.reduceRight()

  * CVE-2011-2363
  Multiple dangling pointer vulnerabilities

  * CVE-2011-2362
  Cookie isolation error

  * CVE-2011-2366
  Stealing of cross-domain images using WebGL textures

  * CVE-2011-2368
  Multiple WebGL crashes

  * CVE-2011-2369
  XSS encoding hazard with inline SVG

  * CVE-2011-2370
  Non-whitelisted site can trigger xpinstall");

  script_tag(name:"solution", value:"Please install the updated package(s).");

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

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~5.0~0.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-openSUSE", rpm:"MozillaFirefox-branding-openSUSE~5.0~2.3.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~5.0~0.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~5.0~0.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~5.0~0.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~5.0~0.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~3.1.11~0.7.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~3.1.11~0.7.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~3.1.11~0.7.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~3.1.11~0.7.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~3.1.11~0.7.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.1.2~9.7.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js192", rpm:"mozilla-js192~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-buildsymbols", rpm:"mozilla-xulrunner192-buildsymbols~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-devel", rpm:"mozilla-xulrunner192-devel~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common", rpm:"mozilla-xulrunner192-translations-common~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other", rpm:"mozilla-xulrunner192-translations-other~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js192-32bit", rpm:"mozilla-js192-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome-32bit", rpm:"mozilla-xulrunner192-gnome-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common-32bit", rpm:"mozilla-xulrunner192-translations-common-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other-32bit", rpm:"mozilla-xulrunner192-translations-other-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE11.3") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.6.18~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.6.18~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~3.6.18~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~3.6.18~0.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~3.1.11~0.11.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~3.1.11~0.11.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~3.1.11~0.11.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~3.1.11~0.11.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.1.2~9.11.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js192", rpm:"mozilla-js192~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192", rpm:"mozilla-xulrunner192~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-buildsymbols", rpm:"mozilla-xulrunner192-buildsymbols~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-devel", rpm:"mozilla-xulrunner192-devel~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome", rpm:"mozilla-xulrunner192-gnome~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common", rpm:"mozilla-xulrunner192-translations-common~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other", rpm:"mozilla-xulrunner192-translations-other~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-js192-32bit", rpm:"mozilla-js192-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-32bit", rpm:"mozilla-xulrunner192-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-gnome-32bit", rpm:"mozilla-xulrunner192-gnome-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-common-32bit", rpm:"mozilla-xulrunner192-translations-common-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner192-translations-other-32bit", rpm:"mozilla-xulrunner192-translations-other-32bit~1.9.2.18~1.2.1", rls:"openSUSE11.3"))) {
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
