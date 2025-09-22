# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851963");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2972", "CVE-2018-2973");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:34:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-10-26 06:23:24 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for java-10-openjdk (openSUSE-SU-2018:2206-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:2206-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00008.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-10-openjdk'
  package(s) announced via the openSUSE-SU-2018:2206-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenJDK 10.0.2 fixes the following security issues:

  - CVE-2018-2940: the libraries sub-component contained an easily
  exploitable vulnerability that allowed attackers to compromise Java SE
  or Java SE Embedded over the network, potentially gaining unauthorized
  read access to data that's accessible to the server. [bsc#1101645]

  - CVE-2018-2952: the concurrency sub-component contained a difficult to
  exploit vulnerability that allowed attackers to compromise Java SE, Java
  SE Embedded,
  or JRockit over the network. This issue could have been abused to mount
  a partial denial-of-service attack on the server. [bsc#1101651]

  - CVE-2018-2972: the security sub-component contained a difficult to
  exploit vulnerability that allowed attackers to compromise Java SE over
  the network, potentially gaining unauthorized access to critical data or
  complete access to all Java SE accessible data. [bsc#1101655)

  - CVE-2018-2973: the JSSE sub-component contained a difficult to exploit
  vulnerability allowed attackers to compromise Java SE or Java SE Embedded
  over the network, potentially gaining the ability to create, delete or
  modify critical data or all Java SE, Java SE Embedded accessible data
  without authorization. [bsc#1101656]

  Furthermore, the following bugs were fixed:

  - Properly remove the existing alternative for java before reinstalling
  it. [bsc#1096420]

  - idlj was moved to the *-devel package. [bsc#1096420]

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-810=1");

  script_tag(name:"affected", value:"java-10-openjdk on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk", rpm:"java-10-openjdk~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-accessibility", rpm:"java-10-openjdk-accessibility~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-accessibility-debuginfo", rpm:"java-10-openjdk-accessibility-debuginfo~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-debuginfo", rpm:"java-10-openjdk-debuginfo~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-debugsource", rpm:"java-10-openjdk-debugsource~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-demo", rpm:"java-10-openjdk-demo~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-devel", rpm:"java-10-openjdk-devel~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-headless", rpm:"java-10-openjdk-headless~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-jmods", rpm:"java-10-openjdk-jmods~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-src", rpm:"java-10-openjdk-src~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-10-openjdk-javadoc", rpm:"java-10-openjdk-javadoc~10.0.2.0~lp150.2.3.2", rls:"openSUSELeap15.0"))) {
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
