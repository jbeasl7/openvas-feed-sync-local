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
  script_oid("1.3.6.1.4.1.25623.1.0.852315");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2019-6446");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-01 00:15:00 +0000 (Tue, 01 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-02-26 04:11:55 +0100 (Tue, 26 Feb 2019)");
  script_name("openSUSE: Security Advisory for python-numpy (openSUSE-SU-2019:0245-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:0245-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-02/msg00061.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-numpy'
  package(s) announced via the openSUSE-SU-2019:0245-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-numpy fixes the following issue:

  Security issue fixed:

  - CVE-2019-6446: Set allow_pickle to false by default to restrict loading
  untrusted content (bsc#1122208). With this update we decrease the
  possibility of allowing remote attackers to execute arbitrary code by
  misusing numpy.load(). A warning during runtime will show-up when the
  allow_pickle is not explicitly set.

  NOTE: By applying this update the behavior of python-numpy changes, which
  might break your application. In order to get the old behaviour back, you
  have to explicitly set `allow_pickle` to True. Be aware that this should
  only be done for trusted input, as loading untrusted input might lead to
  arbitrary code execution.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-245=1");

  script_tag(name:"affected", value:"python-numpy on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"python-numpy-debuginfo", rpm:"python-numpy-debuginfo~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-numpy-debugsource", rpm:"python-numpy-debugsource~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-numpy_1_14_0-gnu-hpc-debuginfo", rpm:"python-numpy_1_14_0-gnu-hpc-debuginfo~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-numpy_1_14_0-gnu-hpc-debugsource", rpm:"python-numpy_1_14_0-gnu-hpc-debugsource~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy", rpm:"python2-numpy~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy-debuginfo", rpm:"python2-numpy-debuginfo~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy-devel", rpm:"python2-numpy-devel~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy-gnu-hpc", rpm:"python2-numpy-gnu-hpc~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy-gnu-hpc-devel", rpm:"python2-numpy-gnu-hpc-devel~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy_1_14_0-gnu-hpc", rpm:"python2-numpy_1_14_0-gnu-hpc~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy_1_14_0-gnu-hpc-debuginfo", rpm:"python2-numpy_1_14_0-gnu-hpc-debuginfo~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy_1_14_0-gnu-hpc-devel", rpm:"python2-numpy_1_14_0-gnu-hpc-devel~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy", rpm:"python3-numpy~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-debuginfo", rpm:"python3-numpy-debuginfo~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-devel", rpm:"python3-numpy-devel~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-gnu-hpc", rpm:"python3-numpy-gnu-hpc~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy-gnu-hpc-devel", rpm:"python3-numpy-gnu-hpc-devel~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy_1_14_0-gnu-hpc", rpm:"python3-numpy_1_14_0-gnu-hpc~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy_1_14_0-gnu-hpc-debuginfo", rpm:"python3-numpy_1_14_0-gnu-hpc-debuginfo~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-numpy_1_14_0-gnu-hpc-devel", rpm:"python3-numpy_1_14_0-gnu-hpc-devel~1.14.0~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
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
