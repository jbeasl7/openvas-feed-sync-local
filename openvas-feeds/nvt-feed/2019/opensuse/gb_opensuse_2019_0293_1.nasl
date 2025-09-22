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
  script_oid("1.3.6.1.4.1.25623.1.0.852332");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-19637", "CVE-2018-19638", "CVE-2018-19639", "CVE-2018-19640");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-03-06 04:09:22 +0100 (Wed, 06 Mar 2019)");
  script_name("openSUSE: Security Advisory for supportutils (openSUSE-SU-2019:0293-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:0293-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'supportutils'
  package(s) announced via the openSUSE-SU-2019:0293-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for supportutils fixes the following issues:

  Security issues fixed:

  - CVE-2018-19640: Fixed an issue where  users could kill arbitrary
  processes (bsc#1118463).

  - CVE-2018-19638: Fixed an issue where users could overwrite arbitrary log
  files (bsc#1118460).

  - CVE-2018-19639: Fixed a code execution if run with -v (bsc#1118462).

  - CVE-2018-19637: Fixed an issue where static temporary filename could
  allow overwriting of files (bsc#1117776).

  Other issues fixed:

  - Fixed invalid exit code commands (bsc#1125666).

  - Included additional SUSE separation (bsc#1125609).

  - Merged added listing of locked packages by zypper.

  - Exclude pam.txt per GDPR by default (bsc#1112461).

  - Clarified -x functionality in supportconfig(8) (bsc#1115245).

  - udev service and provide the whole journal content in supportconfig
  (bsc#1051797).

  - supportconfig collects tuned profile settings (bsc#1071545).

  - sfdisk -d no disk device specified (bsc#1043311).

  - Added vulnerabilities status check in basic-health.txt (bsc#1105849).

  - Added only sched_domain from cpu0.

  - Blacklist sched_domain from proc.txt (bsc#1046681).

  - Added firewall-cmd info.

  - Add ls -lA --time-style=long-iso /etc/products.d/

  - Dump lsof errors.

  - Added corosync status to ha_info.

  - Dump find errors in ib_info.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-293=1");

  script_tag(name:"affected", value:"supportutils on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"supportutils", rpm:"supportutils~3.1~lp150.4.3.1", rls:"openSUSELeap15.0"))) {
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
