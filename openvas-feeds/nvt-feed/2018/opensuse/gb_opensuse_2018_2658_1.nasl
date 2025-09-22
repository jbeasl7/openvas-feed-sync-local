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
  script_oid("1.3.6.1.4.1.25623.1.0.851886");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-09-09 07:10:07 +0200 (Sun, 09 Sep 2018)");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362",
                "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366",
                "CVE-2018-12367", "CVE-2018-12371", "CVE-2018-5156", "CVE-2018-5187",
                "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 18:39:00 +0000 (Thu, 06 Dec 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2018:2658-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird to version 60.0 fixes the following
  issues:

  These security issues were fixed:

  - CVE-2018-12359: Prevent buffer overflow using computed size of canvas
  element (bsc#1098998).

  - CVE-2018-12360: Prevent use-after-free when using focus() (bsc#1098998).

  - CVE-2018-12361: Prevent integer overflow in SwizzleData (bsc#1098998).

  - CVE-2018-12362: Prevent integer overflow in SSSE3 scaler (bsc#1098998).

  - CVE-2018-5156: Prevent media recorder segmentation fault when track type
  is changed during capture (bsc#1098998).

  - CVE-2018-12363: Prevent use-after-free when appending DOM nodes
  (bsc#1098998).

  - CVE-2018-12364: Prevent CSRF attacks through 307 redirects and NPAPI
  plugins (bsc#1098998).

  - CVE-2018-12365: Prevent compromised IPC child process listing local
  filenames (bsc#1098998).

  - CVE-2018-12371: Prevent integer overflow in Skia library during edge
  builder allocation (bsc#1098998).

  - CVE-2018-12366: Prevent invalid data handling during QCMS
  transformations (bsc#1098998).

  - CVE-2018-12367: Timing attack mitigation of PerformanceNavigationTiming
  (bsc#1098998).

  - CVE-2018-5187: Various memory safety bugs (bsc#1098998).

  - CVE-2018-5188: Various memory safety bugs (bsc#1098998).

  These can not, in general, be exploited through email, but are potential
  risks in browser or browser-like contexts.

  These non-security issues were fixed:

  - Storing of remote content settings fixed (bsc#1084603)

  - Improved message handling and composing

  - Improved handling of message templates

  - Support for OAuth2 and FIDO U2F

  - Various Calendar improvements

  - Various fixes and changes to e-mail workflow

  - Various IMAP fixes

  - Native desktop notifications

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-994=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-994=1");

  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2658-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-09/msg00015.html");
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
  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~60.0~74.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~60.0~74.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~60.0~74.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~60.0~74.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~60.0~74.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~60.0~74.1", rls:"openSUSELeap42.3"))) {
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
