# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851200");
  script_version("2021-10-14T09:01:39+0000");
  script_tag(name:"last_modification", value:"2021-10-14 09:01:39 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-02-08 06:18:19 +0100 (Mon, 08 Feb 2016)");
  script_cve_id("CVE-2015-7578", "CVE-2015-7579", "CVE-2015-7580");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-08 15:16:00 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for rubygem-rails-html-sanitizer (openSUSE-SU-2016:0356-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-rails-html-sanitizer'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-rails-html-sanitizer fixes the following issues:

  - CVE-2015-7579: XSS vulnerability in rails-html-sanitizer (bsc#963327)

  - CVE-2015-7578: XSS vulnerability via attributes (bsc#963326)

  - CVE-2015-7580: XSS via whitelist sanitizer (bsc#963328)");

  script_tag(name:"affected", value:"rubygem-rails-html-sanitizer on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0356-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-rails-html-sanitizer", rpm:"ruby2.1-rubygem-rails-html-sanitizer~1.0.2~5.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-rails-html-sanitizer-doc", rpm:"ruby2.1-rubygem-rails-html-sanitizer-doc~1.0.2~5.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-rails-html-sanitizer-testsuite", rpm:"uby2.1-rubygem-rails-html-sanitizer-testsuite~1.0.2~5.1", rls:"openSUSELeap42.1"))) {
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
