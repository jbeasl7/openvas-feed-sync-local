# Copyright (C) 2009 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.63223");
  script_version("2025-02-28T05:38:48+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:48 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Advisory for MozillaFirefox, MozillaThunderbird, mozilla (SUSE-SA:2009:002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0|openSUSE10\.3)");

  script_tag(name:"insight", value:"Various Mozilla browser suite programs were updated to the last
security release.

The Mozilla Firefox 3.0.5 browser, Seamonkey 1.1.14 and xulrunner190
update were already published before Christmas, please see
SUSE-SA:2008:058.

Mozilla Firefox for older products was updated to 2.0.0.19 and Mozilla
Thunderbird was updated to 2.0.0.19. Other packages received backports.

For details on the security problems addressed, please visit the
referenced security advisories.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:002");

  script_tag(name:"summary", value:"The remote host is missing updates to Mozilla announced in
advisory SUSE-SA:2009:002.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~2.0.0.19~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~2.0.0.19~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations", rpm:"MozillaThunderbird-translations~2.0.0.19~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181", rpm:"mozilla-xulrunner181~1.8.1.19~1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-devel", rpm:"mozilla-xulrunner181-devel~1.8.1.19~1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-l10n", rpm:"mozilla-xulrunner181-l10n~1.8.1.19~1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~2.0.0.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~2.0.0.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-debuginfo", rpm:"epiphany-debuginfo~2.22.1.1~25.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-debugsource", rpm:"epiphany-debugsource~2.22.1.1~25.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-extensions-debuginfo", rpm:"epiphany-extensions-debuginfo~2.22.0~37.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-extensions-debugsource", rpm:"epiphany-extensions-debugsource~2.22.0~37.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-debuginfo", rpm:"mozilla-xulrunner181-debuginfo~1.8.1.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-debugsource", rpm:"mozilla-xulrunner181-debugsource~1.8.1.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~2.0.0.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~2.0.0.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations", rpm:"MozillaThunderbird-translations~2.0.0.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.22.1.1~25.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.22.1.1~25.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-doc", rpm:"epiphany-doc~2.22.1.1~25.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-extensions", rpm:"epiphany-extensions~2.22.0~37.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181", rpm:"mozilla-xulrunner181~1.8.1.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-devel", rpm:"mozilla-xulrunner181-devel~1.8.1.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-l10n", rpm:"mozilla-xulrunner181-l10n~1.8.1.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~2.0.0.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations", rpm:"MozillaThunderbird-translations~2.0.0.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.20.0~8.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.20.0~8.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-doc", rpm:"epiphany-doc~2.20.0~8.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"epiphany-extensions", rpm:"epiphany-extensions~2.20.0~8.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181", rpm:"mozilla-xulrunner181~1.8.1.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-devel", rpm:"mozilla-xulrunner181-devel~1.8.1.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-l10n", rpm:"mozilla-xulrunner181-l10n~1.8.1.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-32bit", rpm:"mozilla-xulrunner181-32bit~1.8.1.19~1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-l10n-32bit", rpm:"mozilla-xulrunner181-l10n-32bit~1.8.1.19~1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-32bit", rpm:"mozilla-xulrunner181-32bit~1.8.1.19~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner181-32bit", rpm:"mozilla-xulrunner181-32bit~1.8.1.19~0.1", rls:"openSUSE10.3"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
