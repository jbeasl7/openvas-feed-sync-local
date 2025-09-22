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
  script_oid("1.3.6.1.4.1.25623.1.0.66459");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-4022");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("SUSE: Security Advisory for bind (SUSE-SA:2009:059)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.2|openSUSE11\.1|openSUSE11\.0)");

  script_tag(name:"insight", value:"The bind DNS server was updated to close a possible cache poisoning
vulnerability which allowed to bypass DNSSEC.

This problem can only happen after the other spoofing/poisoning
mechanisms have been bypassed already (the port and transaction id
randomization). Also this can only happen if the server is setup for
DNSSEC. Due to this limitation we consider this a minor issue.

The DNSSEC implementation was redone in 2004 and implemented in
bind 9.6.

Earlier bind version do not support the DNSSEC version and so are not
affected.

This means that the Bind versions of SUSE Linux Enterprise Server 9
(bind 9.3.4) and SUSE Linux Enterprise Server 10 (bind 9.3.4) are
not affected by this problem.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:059");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:059.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs-64bit", rpm:"bind-libs-64bit~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-devel-64bit", rpm:"bind-devel-64bit~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs-64bit", rpm:"bind-libs-64bit~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs-debuginfo-32bit", rpm:"bind-libs-debuginfo-32bit~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.6.1P2~1.1.1", rls:"openSUSE11.2"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.5.0P2~18.8.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.4.2~39.8", rls:"openSUSE11.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
