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
  script_oid("1.3.6.1.4.1.25623.1.0.851848");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-08-10 06:01:09 +0200 (Fri, 10 Aug 2018)");
  script_cve_id("CVE-2018-5807", "CVE-2018-5810", "CVE-2018-5811", "CVE-2018-5812", "CVE-2018-5813", "CVE-2018-5815");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for libraw (openSUSE-SU-2018:2286-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libraw fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-5813: Fixed an error within the 'parse_minolta()' function
  (dcraw/dcraw.c) that could be exploited to trigger an infinite loop via
  a specially crafted file. This could be exploited to cause a
  DoS.(boo#1103200).

  - CVE-2018-5815: Fixed an integer overflow in the
  internal/dcraw_common.cpp:parse_qt() function, that could be exploited
  to cause an infinite loop via a specially crafted Apple QuickTime file.
  (boo#1103206)

  - CVE-2018-5810: Fixed an error within the rollei_load_raw() function
  (internal/dcraw_common.cpp) that could be exploited to cause a
  heap-based buffer overflow and subsequently cause a crash. (boo#1103353)

  - CVE-2018-5811: Fixed an error within the nikon_coolscan_load_raw()
  function (internal/dcraw_common.cpp) that could be exploited to cause an
  out-of-bounds read memory access and subsequently cause a crash.
  (boo#1103359)

  - CVE-2018-5812: Fixed another error within the nikon_coolscan_load_raw()
  function (internal/dcraw_common.cpp) that could be exploited to trigger
  a NULL pointer dereference. (boo#1103360)

  - CVE-2018-5807: Fixed an error within the samsung_load_raw() function
  (internal/dcraw_common.cpp) that could be exploited to cause an
  out-of-bounds read memory access and subsequently cause a crash.
  (boo#1103361)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-849=1");

  script_tag(name:"affected", value:"libraw on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2286-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00032.html");
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
  if(!isnull(res = isrpmvuln(pkg:"libraw-debugsource", rpm:"libraw-debugsource~0.17.1~23.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.17.1~23.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel-static", rpm:"libraw-devel-static~0.17.1~23.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.17.1~23.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-tools-debuginfo", rpm:"libraw-tools-debuginfo~0.17.1~23.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw15", rpm:"libraw15~0.17.1~23.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw15-debuginfo", rpm:"libraw15-debuginfo~0.17.1~23.1", rls:"openSUSELeap42.3"))) {
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
