# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850651");
  script_version("2022-07-05T11:37:00+0000");
  script_cve_id("CVE-2014-2977", "CVE-2014-2978");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-05-01 05:48:51 +0200 (Fri, 01 May 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for DirectFB (openSUSE-SU-2015:0807-1)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'DirectFB'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"DirectFB was updated to fix two security issues.

  The following vulnerabilities were fixed:

  * CVE-2014-2977: Multiple integer signedness errors could allow remote
  attackers to cause a denial of service (crash) and possibly execute
  arbitrary code via the Voodoo interface, which triggers a stack-based
  buffer overflow.

  * CVE-2014-2978: Remote attackers could cause a denial of service (crash)
  and possibly execute arbitrary code via the Voodoo interface, which
  triggers an out-of-bounds write.");

  script_tag(name:"affected", value:"DirectFB on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:0807-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"DirectFB", rpm:"DirectFB~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-Mesa", rpm:"DirectFB-Mesa~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-Mesa-debuginfo", rpm:"DirectFB-Mesa-debuginfo~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-debuginfo", rpm:"DirectFB-debuginfo~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-debugsource", rpm:"DirectFB-debugsource~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-devel", rpm:"DirectFB-devel~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-doc", rpm:"DirectFB-doc~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-libSDL", rpm:"DirectFB-libSDL~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-libSDL-debuginfo", rpm:"DirectFB-libSDL-debuginfo~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-libvncclient", rpm:"DirectFB-libvncclient~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-libvncclient-debuginfo", rpm:"DirectFB-libvncclient-debuginfo~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdirectfb-1_6-0", rpm:"libdirectfb-1_6-0~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdirectfb-1_6-0-debuginfo", rpm:"libdirectfb-1_6-0-debuginfo~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"DirectFB-devel-32bit", rpm:"DirectFB-devel-32bit~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdirectfb-1_6-0-32bit", rpm:"libdirectfb-1_6-0-32bit~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdirectfb-1_6-0-debuginfo-32bit", rpm:"libdirectfb-1_6-0-debuginfo-32bit~1.6.3~4.3.1", rls:"openSUSE13.1"))) {
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
