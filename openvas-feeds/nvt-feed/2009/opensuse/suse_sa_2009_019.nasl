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
  script_oid("1.3.6.1.4.1.25623.1.0.63799");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Advisory for krb5 (SUSE-SA:2009:019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0|openSUSE10\.3)");

  script_tag(name:"insight", value:"The Kerberos implementation from MIT is vulnerable to four
different security issues that range from a remote crash to
possible, but very unlikely, remote code execution.

  - CVE-2009-0844: The SPNEGO GSS-API implementation can read
beyond the end of a buffer (network input) which leads to a
crash.

  - CVE-2009-0845: A NULL pointer dereference in the SPNEGO code
can lead to a crash which affects programs using the GSS-API.

  - CVE-2009-0846: The ASN.1 decoder can free an uninitialized NULL
pointer which leads to a crash and can possibly lead to remote
code execution. This bug can be exploited before any authen-
tication happened,

  - CVE-2009-0847: The ASN.1 decoder incorrectly validates a length
parameter which leads to malloc() errors any possibly to a crash.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:019");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:019.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debugsource", rpm:"krb5-debugsource~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-clients", rpm:"krb5-apps-clients~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-apps-servers", rpm:"krb5-apps-servers~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-client", rpm:"krb5-client~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo-64bit", rpm:"krb5-debuginfo-64bit~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-64bit", rpm:"krb5-64bit~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-64bit", rpm:"krb5-devel-64bit~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-debuginfo-32bit", rpm:"krb5-debuginfo-32bit~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~132.3.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~132.5.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~50.3", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.3~50.5", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-32bit", rpm:"krb5-32bit~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.2~22.7", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"krb5-devel-32bit", rpm:"krb5-devel-32bit~1.6.2~22.9", rls:"openSUSE10.3"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
