# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850318");
  script_version("2022-07-05T11:37:01+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:01 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:41 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-2763", "CVE-2012-3236", "CVE-2012-3403", "CVE-2012-3481");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:1080-1");
  script_name("openSUSE: Security Advisory for gimp (openSUSE-SU-2012:1080-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE12\.1)");

  script_tag(name:"affected", value:"gimp on openSUSE 12.1, openSUSE 11.4");

  script_tag(name:"insight", value:"Multiple integer overflows in various decoder plug-ins of
  GIMP have been fixed.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

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
  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-branding-upstream", rpm:"gimp-branding-upstream~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debugsource", rpm:"gimp-debugsource~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-debuginfo", rpm:"gimp-devel-debuginfo~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-help-browser", rpm:"gimp-help-browser~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-help-browser-debuginfo", rpm:"gimp-help-browser-debuginfo~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-module-hal", rpm:"gimp-module-hal~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-module-hal-debuginfo", rpm:"gimp-module-hal-debuginfo~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugins-python", rpm:"gimp-plugins-python~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugins-python-debuginfo", rpm:"gimp-plugins-python-debuginfo~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0", rpm:"libgimp-2_0-0~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo", rpm:"libgimp-2_0-0-debuginfo~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0", rpm:"libgimpui-2_0-0~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo", rpm:"libgimpui-2_0-0-debuginfo~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-32bit", rpm:"libgimp-2_0-0-32bit~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo-32bit", rpm:"libgimp-2_0-0-debuginfo-32bit~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-32bit", rpm:"libgimpui-2_0-0-32bit~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo-32bit", rpm:"libgimpui-2_0-0-debuginfo-32bit~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-lang", rpm:"gimp-lang~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo-x86", rpm:"libgimp-2_0-0-debuginfo-x86~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-x86", rpm:"libgimp-2_0-0-x86~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo-x86", rpm:"libgimpui-2_0-0-debuginfo-x86~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-x86", rpm:"libgimpui-2_0-0-x86~2.6.11~13.58.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debugsource", rpm:"gimp-debugsource~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-debuginfo", rpm:"gimp-devel-debuginfo~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-help-browser", rpm:"gimp-help-browser~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-help-browser-debuginfo", rpm:"gimp-help-browser-debuginfo~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugins-python", rpm:"gimp-plugins-python~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-plugins-python-debuginfo", rpm:"gimp-plugins-python-debuginfo~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0", rpm:"libgimp-2_0-0~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo", rpm:"libgimp-2_0-0-debuginfo~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0", rpm:"libgimpui-2_0-0~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo", rpm:"libgimpui-2_0-0-debuginfo~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-32bit", rpm:"libgimp-2_0-0-32bit~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo-32bit", rpm:"libgimp-2_0-0-debuginfo-32bit~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-32bit", rpm:"libgimpui-2_0-0-32bit~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo-32bit", rpm:"libgimpui-2_0-0-debuginfo-32bit~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-branding-upstream", rpm:"gimp-branding-upstream~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-lang", rpm:"gimp-lang~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-debuginfo-x86", rpm:"libgimp-2_0-0-debuginfo-x86~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimp-2_0-0-x86", rpm:"libgimp-2_0-0-x86~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-debuginfo-x86", rpm:"libgimpui-2_0-0-debuginfo-x86~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgimpui-2_0-0-x86", rpm:"libgimpui-2_0-0-x86~2.6.11~28.26.1", rls:"openSUSE12.1"))) {
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
