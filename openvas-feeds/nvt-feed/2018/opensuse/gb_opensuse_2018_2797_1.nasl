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
  script_oid("1.3.6.1.4.1.25623.1.0.851901");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-09-22 07:44:07 +0200 (Sat, 22 Sep 2018)");
  script_cve_id("CVE-2018-17141");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for hylafax+ (openSUSE-SU-2018:2797-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hylafax+'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hylafax+ fixes the following issues:

  Security issues fixed in 5.6.1:

  - CVE-2018-17141: multiple vulnerabilities affecting fax page reception in
  JPEG format Specially crafted input may have allowed remote execution of
  arbitrary code (boo#1109084)

  Additionally, this update also contains all upstream corrections and
  bugfixes in the 5.6.1 version, including:

  - fix RFC2047 encoding by notify

  - add jobcontrol PageSize feature

  - don't wait forever after +FRH:3

  - fix faxmail transition between a message and external types

  - avoid pagehandling from introducing some unnecessary EOM signals

  - improve proxy connection error handling and logging

  - add initial ModemGroup limits feature

  - pass the user's uid onto the session log file for sent faxes

  - improve job waits to minimize triggers

  - add ProxyTaglineFormat and ProxyTSI features

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1027=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1027=1");

  script_tag(name:"affected", value:"hylafax+ on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2797-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00044.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"hylafax+", rpm:"hylafax+~5.6.1~15.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-client", rpm:"hylafax+-client~5.6.1~15.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-client-debuginfo", rpm:"hylafax+-client-debuginfo~5.6.1~15.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-debuginfo", rpm:"hylafax+-debuginfo~5.6.1~15.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-debugsource", rpm:"hylafax+-debugsource~5.6.1~15.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfaxutil5_6_1", rpm:"libfaxutil5_6_1~5.6.1~15.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfaxutil5_6_1-debuginfo", rpm:"libfaxutil5_6_1-debuginfo~5.6.1~15.1", rls:"openSUSELeap42.3"))) {
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
