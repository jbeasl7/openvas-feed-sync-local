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
  script_oid("1.3.6.1.4.1.25623.1.0.63610");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2009-0040", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Advisory for MozillaFirefox (SUSE-SA:2009:012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0)");

  script_tag(name:"insight", value:"The Mozilla Firefox browser is updated to version 3.0.7 fixing various
security and stability issues.

Updates are provided for openSUSE 11.0 and 11.1 currently, backports
for other Mozilla Firefox browsers and Mozilla Suite programs will
follow.

MFSA 2009-07 / CVE-2009-0771 / CVE-2009-0772 / CVE-2009-0773 /
CVE-2009-0774: Mozilla developers identified and fixed several
stability bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these crashes showed evidence of memory
corruption under certain circumstances and we presume that with enough
effort at least some of these could be exploited to run arbitrary code.

MFSA 2009-08 / CVE-2009-0775: An anonymous researcher, via
TippingPoint's Zero Day Initiative program, reported a vulnerability in
Mozilla's garbage collection process. The vulnerability was caused by
improper memory management of a set of cloned XUL DOM elements which
were linked as a parent and child. After reloading the browser on a
page with such linked elements, the browser would crash when attempting
to access an object which was already destroyed. An attacker could
use this crash to run arbitrary code on the victim's computer.

MFSA 2009-09 / CVE-2009-0776: Mozilla security researcher Georgi
Guninski reported that a website could use nsIRDFService and a
cross-domain redirect to steal arbitrary XML data from another domain,
a violation of the same-origin policy. This vulnerability could be used
by a malicious website to steal private data from users authenticated
to the redirected website.

MFSA 2009-10 / CVE-2009-0040: libpng maintainer Glenn Randers-Pehrson
reported several memory safety hazards in PNG libraries used by
Mozilla. These vulnerabilities could be used by a malicious website
to crash a victim's browser and potentially execute arbitrary code
on their computer. libpng was upgraded to a version which contained
fixes for these flaws.

MFSA 2009-11 / CVE-2009-0777: Mozilla contributor Masahiro Yamada
reported that certain invisible control characters were being decoded
when displayed in the location bar, resulting in fewer visible
characters than were present in the actual location. An attacker
could use this vulnerability to spoof the location bar and display
a misleading URL for their malicious web page.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:012");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:012.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.7~1.1.6", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.0.7~1.1.6", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.7~1.1.6", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"python-xpcom190", rpm:"python-xpcom190~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~3.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190", rpm:"mozilla-xulrunner190~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-devel", rpm:"mozilla-xulrunner190-devel~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs", rpm:"mozilla-xulrunner190-gnomevfs~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations", rpm:"mozilla-xulrunner190-translations~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-64bit", rpm:"mozilla-xulrunner190-64bit~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-64bit", rpm:"mozilla-xulrunner190-gnomevfs-64bit~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-64bit", rpm:"mozilla-xulrunner190-translations-64bit~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.7~1.2.2", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-32bit", rpm:"mozilla-xulrunner190-32bit~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-gnomevfs-32bit", rpm:"mozilla-xulrunner190-gnomevfs-32bit~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"mozilla-xulrunner190-translations-32bit", rpm:"mozilla-xulrunner190-translations-32bit~1.9.0.7~1.1", rls:"openSUSE11.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
