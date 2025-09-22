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
  script_oid("1.3.6.1.4.1.25623.1.0.851944");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-10-20 07:33:47 +0200 (Sat, 20 Oct 2018)");
  script_cve_id("CVE-2015-8010", "CVE-2016-0726", "CVE-2016-10089", "CVE-2016-8641");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-22 18:32:00 +0000 (Thu, 22 Jun 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for icinga (openSUSE-SU-2018:3258-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icinga'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icinga fixes the following issues:

  Update to 1.14.0

  - CVE-2015-8010: Fixed XSS in the icinga classic UI (boo#952777)

  - CVE-2016-8641 / CVE-2016-10089: fixed a possible symlink attack for
  files/dirs created by root (boo#1011630 and boo#1018047)

  - CVE-2016-0726: removed the pre-configured administrative account with
  fixed password for the WebUI - (boo#961115)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1206=1");

  script_tag(name:"affected", value:"icinga on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:3258-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00043.html");
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
  if(!isnull(res = isrpmvuln(pkg:"icinga", rpm:"icinga~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-debuginfo", rpm:"icinga-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-debugsource", rpm:"icinga-debugsource~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-devel", rpm:"icinga-devel~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-doc", rpm:"icinga-doc~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-idoutils", rpm:"icinga-idoutils~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-idoutils-debuginfo", rpm:"icinga-idoutils-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-idoutils-mysql", rpm:"icinga-idoutils-mysql~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-idoutils-oracle", rpm:"icinga-idoutils-oracle~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-idoutils-pgsql", rpm:"icinga-idoutils-pgsql~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-plugins-downtimes", rpm:"icinga-plugins-downtimes~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-plugins-eventhandlers", rpm:"icinga-plugins-eventhandlers~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-www", rpm:"icinga-www~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-www-config", rpm:"icinga-www-config~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga-www-debuginfo", rpm:"icinga-www-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitoring-tools", rpm:"monitoring-tools~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitoring-tools-debuginfo", rpm:"monitoring-tools-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3"))) {
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
