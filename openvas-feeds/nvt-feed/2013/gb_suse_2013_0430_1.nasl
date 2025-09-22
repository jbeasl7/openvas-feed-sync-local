# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850436");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:51 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"openSUSE-SU", value:"2013:0430-1");
  script_name("openSUSE: Security Advisory for java-1_6_0-openjdk (openSUSE-SU-2013:0430-1)");

  script_tag(name:"affected", value:"java-1_6_0-openjdk on openSUSE 12.1");

  script_tag(name:"insight", value:"java-1_6_0-openjdk aka IcedTea was updated to 1.12.4
  (bnc#807487)

  - S8007014, CVE-2013-0809: Improve image handling

  - S8007675, CVE-2013-1493: Improve color conversion");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_6_0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.1");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk", rpm:"java-1_6_0-openjdk~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-debuginfo", rpm:"java-1_6_0-openjdk-debuginfo~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-debugsource", rpm:"java-1_6_0-openjdk-debugsource~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-demo", rpm:"java-1_6_0-openjdk-demo~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-demo-debuginfo", rpm:"java-1_6_0-openjdk-demo-debuginfo~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-devel", rpm:"java-1_6_0-openjdk-devel~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-devel-debuginfo", rpm:"java-1_6_0-openjdk-devel-debuginfo~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-javadoc", rpm:"java-1_6_0-openjdk-javadoc~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-openjdk-src", rpm:"java-1_6_0-openjdk-src~1.6.0.0_b27.1.12.4~32.1", rls:"openSUSE12.1"))) {
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
