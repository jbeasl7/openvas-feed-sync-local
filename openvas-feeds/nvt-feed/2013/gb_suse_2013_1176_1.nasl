# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850505");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-11-19 14:06:02 +0530 (Tue, 19 Nov 2013)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1682", "CVE-2013-1683", "CVE-2013-1684", "CVE-2013-1685",
                "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1688", "CVE-2013-1690",
                "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1695",
                "CVE-2013-1696", "CVE-2013-1697", "CVE-2013-1698");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:25:57 +0000 (Tue, 09 Jul 2024)");
  script_name("openSUSE: Security Advisory for update (openSUSE-SU-2013:1176-1)");

  script_tag(name:"affected", value:"update on openSUSE 11.4");

  script_tag(name:"insight", value:"Seamonkey was updated to version 2.19

  * MFSA 2013-49/CVE-2013-1682/CVE-2013-1683 Miscellaneous
  memory safety hazards

  * MFSA 2013-50/CVE-2013-1684/CVE-2013-1685/CVE-2013-1686
  Memory corruption found using Address Sanitizer

  * MFSA 2013-51/CVE-2013-1687 (bmo#863933, bmo#866823)
  Privileged content access and execution via XBL

  * MFSA 2013-52/CVE-2013-1688 (bmo#873966) Arbitrary code
  execution within Profiler

  * MFSA 2013-53/CVE-2013-1690 (bmo#857883) Execution of
  unmapped memory through onreadystatechange event

  * MFSA 2013-54/CVE-2013-1692 (bmo#866915) Data in the
  body of XHR HEAD requests leads to CSRF attacks

  * MFSA 2013-55/CVE-2013-1693 (bmo#711043) SVG filters can
  lead to information disclosure

  * MFSA 2013-56/CVE-2013-1694 (bmo#848535) PreserveWrapper
  has inconsistent behavior

  * MFSA 2013-57/CVE-2013-1695 (bmo#849791) Sandbox
  restrictions not applied to nested frame elements

  * MFSA 2013-58/CVE-2013-1696 (bmo#761667) X-Frame-Options
  ignored when using server push with multi-part responses

  * MFSA 2013-59/CVE-2013-1697 (bmo#858101) XrayWrappers
  can be bypassed to run user defined methods in a
  privileged context

  * MFSA 2013-60/CVE-2013-1698 (bmo#876044)");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"openSUSE-SU", value:"2013:1176-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.19~69.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.19~69.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.19~69.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.19~69.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.19~69.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.19~69.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.19~69.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.19~69.1", rls:"openSUSE11.4"))) {
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
