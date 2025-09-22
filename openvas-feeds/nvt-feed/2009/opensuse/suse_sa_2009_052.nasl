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
  script_oid("1.3.6.1.4.1.25623.1.0.66214");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-0689", "CVE-2009-3380", "CVE-2009-3379", "CVE-2009-3378", "CVE-2009-3274", "CVE-2009-3381", "CVE-2009-3382", "CVE-2009-3383", "CVE-2009-3371", "CVE-2009-3370", "CVE-2009-3373", "CVE-2009-3372", "CVE-2009-3375", "CVE-2009-3374", "CVE-2009-3377", "CVE-2009-3376");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Advisory for MozillaFirefox (SUSE-SA:2009:052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0)");

  script_tag(name:"insight", value:"The Mozilla Firefox browser was updated to fix various bugs and
security issues.

For details on the issues addressed in this update, please visit
the referenced security advisories.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:052");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:052.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~3.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~3.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debuginfo", rpm:"mozilla-xulrunner190-debuginfo~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debugsource", rpm:"mozilla-xulrunner190-debugsource~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"python-xpcom190", rpm:"python-xpcom190~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~3.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~3.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debuginfo", rpm:"mozilla-xulrunner190-debuginfo~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debugsource", rpm:"mozilla-xulrunner190-debugsource~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-64bit", rpm:"mozilla-xulrunner190-64bit~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-64bit", rpm:"mozilla-xulrunner190-gnomevfs-64bit~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-64bit", rpm:"mozilla-xulrunner190-translations-64bit~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debuginfo-32bit", rpm:"mozilla-xulrunner190-debuginfo-32bit~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.15~0.1.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.15~0.1", rls:"openSUSE11.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
