# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854733");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2022-29804", "CVE-2022-30580", "CVE-2022-30629", "CVE-2022-30634");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-12 20:46:00 +0000 (Fri, 12 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-06-08 01:02:50 +0000 (Wed, 08 Jun 2022)");
  script_name("openSUSE: Security Advisory for go1.17 (SUSE-SU-2022:2004-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2004-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7YVS6P6QJPK5B4HQAT2XTPVX5KZ5WZ3B");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.17'
  package(s) announced via the SUSE-SU-2022:2004-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.17 fixes the following issues:
  Update to go1.17.11 (released 2022-06-01) (bsc#1190649):

  - CVE-2022-30634: Fixed crypto/rand rand.Read hangs with extremely large
       buffers (bsc#1200134).

  - CVE-2022-30629: Fixed crypto/tls session tickets lack random
       ticket_age_add (bsc#1200135).

  - CVE-2022-29804: Fixed path/filepath Clean(`.\c:`) returns `c:` on
       Windows (bsc#1200137).

  - CVE-2022-30580: Fixed os/exec empty Cmd.Path can result in running
       unintended binary on Windows (bsc#1200136).");

  script_tag(name:"affected", value:"'go1.17' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.17", rpm:"go1.17~1.17.11~150000.1.37.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-doc", rpm:"go1.17-doc~1.17.11~150000.1.37.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-race", rpm:"go1.17-race~1.17.11~150000.1.37.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"go1.17", rpm:"go1.17~1.17.11~150000.1.37.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-doc", rpm:"go1.17-doc~1.17.11~150000.1.37.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.17-race", rpm:"go1.17-race~1.17.11~150000.1.37.1", rls:"openSUSELeap15.3"))) {
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