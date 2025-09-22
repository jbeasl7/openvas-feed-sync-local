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
  script_oid("1.3.6.1.4.1.25623.1.0.851531");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-04-06 06:33:15 +0200 (Thu, 06 Apr 2017)");
  script_cve_id("CVE-2015-7551", "CVE-2016-2339");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-15 01:29:00 +0000 (Sun, 15 Jul 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for ruby2.2 (openSUSE-SU-2017:0933-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.2'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.2, ruby2.3 fixes the following issues:

  Security issues fixed:

  - CVE-2016-2339: heap overflow vulnerability in the
  Fiddle::Function.new'initialize' (boo#1018808)

  - CVE-2015-7551: Unsafe tainted string usage in Fiddle and DL (boo#959495)

  Detailed ChangeLog are linked in the references.");

  script_xref(name:"URL", value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_2_6/ChangeLog");
  script_xref(name:"URL", value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_3_3/ChangeLog");

  script_tag(name:"affected", value:"ruby2.2, on openSUSE Leap 42.2, openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:0933-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"libruby2_2-2_2", rpm:"libruby2_2-2_2~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_2-2_2-debuginfo", rpm:"libruby2_2-2_2-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_3-2_3", rpm:"libruby2_3-2_3~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_3-2_3-debuginfo", rpm:"libruby2_3-2_3-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2", rpm:"ruby2.2~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-debuginfo", rpm:"ruby2.2-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-debugsource", rpm:"ruby2.2-debugsource~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-devel", rpm:"ruby2.2-devel~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-devel-extra", rpm:"ruby2.2-devel-extra~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-doc", rpm:"ruby2.2-doc~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-stdlib", rpm:"ruby2.2-stdlib~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-stdlib-debuginfo", rpm:"ruby2.2-stdlib-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-tk", rpm:"ruby2.2-tk~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-tk-debuginfo", rpm:"ruby2.2-tk-debuginfo~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3", rpm:"ruby2.3~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-debuginfo", rpm:"ruby2.3-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-debugsource", rpm:"ruby2.3-debugsource~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-devel", rpm:"ruby2.3-devel~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-devel-extra", rpm:"ruby2.3-devel-extra~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-doc", rpm:"ruby2.3-doc~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-stdlib", rpm:"ruby2.3-stdlib~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-stdlib-debuginfo", rpm:"ruby2.3-stdlib-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-tk", rpm:"ruby2.3-tk~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-tk-debuginfo", rpm:"ruby2.3-tk-debuginfo~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-doc-ri", rpm:"ruby2.2-doc-ri~2.2.6~6.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.3-doc-ri", rpm:"ruby2.3-doc-ri~2.3.3~2.3.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"libruby2_2-2_2", rpm:"libruby2_2-2_2~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_2-2_2-debuginfo", rpm:"libruby2_2-2_2-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2", rpm:"ruby2.2~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-debuginfo", rpm:"ruby2.2-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-debugsource", rpm:"ruby2.2-debugsource~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-devel", rpm:"ruby2.2-devel~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-devel-extra", rpm:"ruby2.2-devel-extra~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-doc", rpm:"ruby2.2-doc~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-stdlib", rpm:"ruby2.2-stdlib~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-stdlib-debuginfo", rpm:"ruby2.2-stdlib-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-tk", rpm:"ruby2.2-tk~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.2-tk-debuginfo", rpm:"ruby2.2-tk-debuginfo~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uby2.2-doc-ri", rpm:"uby2.2-doc-ri~2.2.6~6.1", rls:"openSUSELeap42.1"))) {
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
