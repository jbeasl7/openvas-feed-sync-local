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
  script_oid("1.3.6.1.4.1.25623.1.0.63735");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
  script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Advisory for Sun Java 5 and 6 (SUSE-SA:2009:016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0|openSUSE10\.3)");

  script_tag(name:"insight", value:"The Sun JDK 5 was updated to Update18 and the Sun JDK 6 was updated
to Update 13 to fix various bugs and security issues.

For details addressed in these updates, please visit the referenced
security advisories.

No Sun Java 1.4.2 updates are available at this time since it has
entered EOL phase.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:016");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:016.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update18~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update18~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update18~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update18~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update18~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update18~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u13~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u13~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u13~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u13~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u13~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u13~0.1.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update18~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update18~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_update18~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update18~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update18~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update18~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update18~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u13~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u13~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-demo", rpm:"java-1_6_0-sun-demo~1.6.0.u13~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u13~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u13~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u13~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u13~0.1", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun", rpm:"java-1_5_0-sun~1.5.0_update18~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-alsa", rpm:"java-1_5_0-sun-alsa~1.5.0_update18~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-demo", rpm:"java-1_5_0-sun-demo~1.5.0_update18~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-devel", rpm:"java-1_5_0-sun-devel~1.5.0_update18~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-jdbc", rpm:"java-1_5_0-sun-jdbc~1.5.0_update18~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-plugin", rpm:"java-1_5_0-sun-plugin~1.5.0_update18~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_5_0-sun-src", rpm:"java-1_5_0-sun-src~1.5.0_update18~0.1", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun", rpm:"java-1_6_0-sun~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-alsa", rpm:"java-1_6_0-sun-alsa~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-debuginfo", rpm:"java-1_6_0-sun-debuginfo~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-demo", rpm:"java-1_6_0-sun-demo~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-devel", rpm:"java-1_6_0-sun-devel~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-jdbc", rpm:"java-1_6_0-sun-jdbc~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-plugin", rpm:"java-1_6_0-sun-plugin~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-sun-src", rpm:"java-1_6_0-sun-src~1.6.0.u12~1.4", rls:"openSUSE10.3"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
