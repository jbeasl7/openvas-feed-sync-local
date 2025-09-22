# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850849");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-10-15 12:15:44 +0200 (Thu, 15 Oct 2015)");
  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591",
                "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395",
                "CVE-2015-0400", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410",
                "CVE-2015-0412");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for java-1_7_0-openjdk (SUSE-SU-2015:0503-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes 13 security issues.

  These security issues were fixed:

  - CVE-2015-0395: Unspecified vulnerability in Oracle Java SE 5.0u75, 6u85,
  7u72, and 8u25 allowed remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors related to Hotspot
  (bnc#914041).

  - CVE-2015-0400: Unspecified vulnerability in Oracle Java SE 6u85, 7u72,
  and 8u25 allowed remote attackers to affect confidentiality via unknown
  vectors related to Libraries (bnc#914041).

  - CVE-2015-0383: Unspecified vulnerability in Oracle Java SE 5.0u75, 6u85,
  7u72, and 8u25  Java SE Embedded 7u71 and 8u6  and JRockit R27.8.4 and
  R28.3.4 allowed local users to affect integrity and availability via
  unknown vectors related to Hotspot (bnc#914041).

  - CVE-2015-0412: Unspecified vulnerability in Oracle Java SE 6u85, 7u72,
  and 8u25 allowed remote attackers to affect confidentiality, integrity,
  and availability via vectors related to JAX-WS (bnc#914041).

  - CVE-2015-0407: Unspecified vulnerability in Oracle Java SE 5.0u75, 6u85,
  7u72, and 8u25 allowed remote attackers to affect confidentiality via
  unknown vectors related to Swing (bnc#914041).

  - CVE-2015-0408: Unspecified vulnerability in Oracle Java SE 5.0u75, 6u85,
  7u72, and 8u25 allowed remote attackers to affect confidentiality,
  integrity, and availability via vectors related to RMI (bnc#914041).

  - CVE-2014-6585: Unspecified vulnerability in Oracle Java SE 5.0u75, 6u85,
  7u72, and 8u25 allowed remote attackers to affect confidentiality via
  unknown vectors reelated to 2D, a different vulnerability than
  CVE-2014-6591 (bnc#914041).

  - CVE-2014-6587: Unspecified vulnerability in Oracle Java SE 6u85, 7u72,
  and 8u25 allowed local users to affect confidentiality, integrity, and
  availability via unknown vectors related to Libraries (bnc#914041).

  - CVE-2014-6591: Unspecified vulnerability in the Java SE component in
  Oracle Java SE 5.0u75, 6u85, 7u72, and 8u25 allowed remote attackers to
  affect confidentiality via unknown vectors related to 2D, a different
  vulnerability than CVE-2014-6585 (bnc#914041).

  - CVE-2014-6593: Unspecified vulnerability in Oracle Java SE 5.0u75, 6u85,
  7u72, and 8u25  Java SE Embedded 7u71 and 8u6  and JRockit 27.8.4 and
  28.3.4 allowed remote attackers to affect confidentiality and integrity
  via vectors related to JSSE (bnc#914041).

  - CVE-2014-6601: Unspecified vulnerability in Oracle Java SE 6u85, 7u72,
  and 8u25 allowed remote attackers to affect confidentiality, integrity,
  and availability via unknown vectors related to Hotspot (b ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"java-1_7_0-openjdk on SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:0503-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.75~11.3", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.75~11.3", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.75~11.3", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.75~11.3", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.75~11.3", rls:"SLED12.0SP0"))) {
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
