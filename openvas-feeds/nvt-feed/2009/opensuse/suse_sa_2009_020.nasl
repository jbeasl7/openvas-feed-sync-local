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
  script_oid("1.3.6.1.4.1.25623.1.0.63845");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
  script_cve_id("CVE-2009-1185", "CVE-2009-1186");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SUSE: Security Advisory for udev (SUSE-SA:2009:020)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.1|openSUSE11\.0|openSUSE10\.3)");

  script_tag(name:"insight", value:"Sebastian Krahmer of SUSE Security identified a problem in udevd with
handling of netlink messages.

Local attackers could inject netlink messages due to a missing origin
check where only the kernel should have been able to and so are able
to escalate privileges. (CVE-2009-1185)

Fixed packages have been released to address this issue for openSUSE
10.3-11.1, SUSE Linux Enterprise 10 SP2 and SUSE Linux Enterprise 11.

SUSE Linux Enterprise Server 9 and Novell Linux Desktop 9 are not
affected by this problem.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SUSE-SA:2009:020");

  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory SUSE-SA:2009:020.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~128~9.7.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libudev0", rpm:"libudev0~128~9.7.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libvolume_id", rpm:"libvolume_id~126~17.38.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libvolume_id-devel", rpm:"libvolume_id-devel~128~9.7.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libvolume_id1", rpm:"libvolume_id1~128~9.7.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~128~9.7.1", rls:"openSUSE11.1"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libvolume_id", rpm:"libvolume_id~120~13.2", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libvolume_id-devel", rpm:"libvolume_id-devel~120~13.2", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~120~13.2", rls:"openSUSE11.0"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libvolume_id", rpm:"libvolume_id~114~19.3", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"libvolume_id-devel", rpm:"libvolume_id-devel~114~19.3", rls:"openSUSE10.3"))) {
  report += res;
}
if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~114~19.3", rls:"openSUSE10.3"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
