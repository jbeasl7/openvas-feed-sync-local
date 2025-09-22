# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852634");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2019-12904");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 21:05:00 +0000 (Thu, 04 Mar 2021)");
  script_tag(name:"creation_date", value:"2019-07-24 02:01:43 +0000 (Wed, 24 Jul 2019)");
  script_name("openSUSE: Security Advisory for libgcrypt (openSUSE-SU-2019:1792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1792-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00049.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt'
  package(s) announced via the openSUSE-SU-2019:1792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgcrypt fixes the following issues:

  Security issues fixed:

  - CVE-2019-12904: The C implementation of AES is vulnerable to a
  flush-and-reload side-channel attack because physical addresses are
  available to other processes. (The C implementation is used on platforms
  where an assembly-language implementation is unavailable.) (bsc#1138939)

  Other bugfixes:

  - Don't run full FIPS self-tests from constructor (bsc#1097073)

  - Skip all the self-tests except for binary integrity when called from the
  constructor (bsc#1097073)

  - Enforce the minimal RSA keygen size in fips mode (bsc#1125740)

  - avoid executing some tests twice.

  - Fixed a race condition in initialization.

  - Fixed env-script-interpreter in cavs_driver.pl

  - Fixed redundant fips tests in some situations causing failure to boot in
  fips mode. (bsc#1097073)

  This helps during booting of the system in FIPS mode with insufficient
  entropy.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1792=1");

  script_tag(name:"affected", value:"'libgcrypt' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-cavs", rpm:"libgcrypt-cavs~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-cavs-debuginfo", rpm:"libgcrypt-cavs-debuginfo~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-debugsource", rpm:"libgcrypt-debugsource~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel-debuginfo", rpm:"libgcrypt-devel-debuginfo~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20", rpm:"libgcrypt20~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-debuginfo", rpm:"libgcrypt20-debuginfo~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac", rpm:"libgcrypt20-hmac~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel-32bit", rpm:"libgcrypt-devel-32bit~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel-32bit-debuginfo", rpm:"libgcrypt-devel-32bit-debuginfo~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit", rpm:"libgcrypt20-32bit~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit-debuginfo", rpm:"libgcrypt20-32bit-debuginfo~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac-32bit", rpm:"libgcrypt20-hmac-32bit~1.8.2~lp150.5.10.1", rls:"openSUSELeap15.0"))) {
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
