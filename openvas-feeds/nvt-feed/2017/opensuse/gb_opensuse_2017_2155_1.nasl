# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851589");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-08-12 07:30:10 +0200 (Sat, 12 Aug 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for tcmu-runner (openSUSE-SU-2017:2155-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcmu-runner'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcmu-runner fixes the following issues:

  - qcow handler opens up an information leak via the CheckConfig D-Bus
  method (bsc#1049491)

  - glfs handler allows local DoS via crafted CheckConfig strings
  (bsc#1049485)

  - UnregisterHandler dbus method in tcmu-runner daemon for non-existing
  handler causes denial of service (bsc#1049488)

  - UnregisterHandler D-Bus method in tcmu-runner daemon for internal
  handler causes denial of service (bsc#1049489)

  - Memory leaks can be triggered in tcmu-runner daemon by calling D-Bus
  method for (Un)RegisterHandler (bsc#1049490)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.");

  script_tag(name:"affected", value:"tcmu-runner on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:2155-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
  if(!isnull(res = isrpmvuln(pkg:"libtcmu-devel", rpm:"libtcmu-devel~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtcmu1", rpm:"libtcmu1~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtcmu1-debuginfo", rpm:"libtcmu1-debuginfo~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcmu-runner", rpm:"tcmu-runner~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcmu-runner-debuginfo", rpm:"tcmu-runner-debuginfo~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcmu-runner-debugsource", rpm:"tcmu-runner-debugsource~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcmu-runner-devel", rpm:"tcmu-runner-devel~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcmu-runner-handler-rbd", rpm:"tcmu-runner-handler-rbd~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcmu-runner-handler-rbd-debuginfo", rpm:"tcmu-runner-handler-rbd-debuginfo~1.2.0~3.1", rls:"openSUSELeap42.3"))) {
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
