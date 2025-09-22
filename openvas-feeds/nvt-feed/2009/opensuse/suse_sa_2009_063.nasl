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
  script_oid("1.3.6.1.4.1.25623.1.0.66601");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3388", "CVE-2009-3389", "CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982", "CVE-2009-3983", "CVE-2009-3984", "CVE-2009-3985", "CVE-2009-3986");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Advisory for MozillaFirefox (SUSE-SA:2009:063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.2|openSUSE11\.1|openSUSE11\.0)");

  script_tag(name:"insight", value:"The Mozilla Firefox browsers and XUL engines were updated to the
current stable releases fixing lots of bugs and various security
issues.

SUSE Linux Enterprise 10 SP2, SP3, SUSE Linux Enterprise 11 and
openSUSE 11.2 were updated to Firefox 3.5.6.
openSUSE 11.0 and 11.1 were updated to Firefox 3.0.16.

The following security issues were fixed:

  * MFSA 2009-65/CVE-2009-3979/CVE-2009-3980/CVE-2009-3982
Crashes with evidence of memory corruption (rv:1.9.1.6)
CVSS v2 Base Score: 9.3 (AV:N/AC:M/Au:N/C:C/I:C/A:C)

  * MFSA 2009-66/CVE-2009-3388 (bmo#504843, bmo#523816)
Memory safety fixes in liboggplay media library
CVSS v2 Base Score: 9.3 (AV:N/AC:M/Au:N/C:C/I:C/A:C)

  * MFSA 2009-67/CVE-2009-3389 (bmo#515882, bmo#504613)
Integer overflow, crash in libtheora video library
CVSS v2 Base Score: 9.3 (AV:N/AC:M/Au:N/C:C/I:C/A:C)

  * MFSA 2009-68/CVE-2009-3983 (bmo#487872)
NTLM reflection vulnerability
CVSS v2 Base Score: 6.8 (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  * MFSA 2009-69/CVE-2009-3984/CVE-2009-3985 (bmo#521461, bmo#514232)
Location bar spoofing vulnerabilities
CVSS v2 Base Score: 6.8 (AV:N/AC:M/Au:N/C:P/I:P/A:P)


  * MFSA 2009-70/CVE-2009-3986 (bmo#522430)
Privilege escalation via chrome window.opener
CVSS v2 Base Score: 7.6 (AV:N/AC:H/Au:N/C:C/I:C/A:C)");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:063");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:063.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~3.5.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~3.5.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-debuginfo", rpm:"mozilla-xulrunner191-debuginfo~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-debugsource", rpm:"mozilla-xulrunner191-debugsource~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"python-xpcom191-debuginfo", rpm:"python-xpcom191-debuginfo~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.5.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.5.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~3.5.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~3.5.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191", rpm:"mozilla-xulrunner191~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-devel", rpm:"mozilla-xulrunner191-devel~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs", rpm:"mozilla-xulrunner191-gnomevfs~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-translations-common", rpm:"mozilla-xulrunner191-translations-common~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-translations-other", rpm:"mozilla-xulrunner191-translations-other~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"python-xpcom191", rpm:"python-xpcom191~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~3.0.16~0.2.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~3.0.16~0.2.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debuginfo", rpm:"mozilla-xulrunner190-debuginfo~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debugsource", rpm:"mozilla-xulrunner190-debugsource~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.16~0.2.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.0.16~0.2.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.16~0.2.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"python-xpcom190", rpm:"python-xpcom190~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~3.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~3.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debuginfo", rpm:"mozilla-xulrunner190-debuginfo~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debugsource", rpm:"mozilla-xulrunner190-debugsource~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-64bit", rpm:"mozilla-xulrunner190-64bit~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-64bit", rpm:"mozilla-xulrunner190-gnomevfs-64bit~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-64bit", rpm:"mozilla-xulrunner190-translations-64bit~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-debuginfo-32bit", rpm:"mozilla-xulrunner191-debuginfo-32bit~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-32bit", rpm:"mozilla-xulrunner191-32bit~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs-32bit", rpm:"mozilla-xulrunner191-gnomevfs-32bit~1.9.1.6~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-debuginfo-32bit", rpm:"mozilla-xulrunner190-debuginfo-32bit~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.16~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.16~0.1", rls:"openSUSE11.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
