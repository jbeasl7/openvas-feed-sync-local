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
  script_oid("1.3.6.1.4.1.25623.1.0.851165");
  script_version("2021-10-13T12:01:28+0000");
  script_tag(name:"last_modification", value:"2021-10-13 12:01:28 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-01-25 06:12:40 +0100 (Mon, 25 Jan 2016)");
  script_cve_id("CVE-2015-8770");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:58:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for roundcubemail (openSUSE-SU-2016:0214-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.0.8

  - Fix HTML sanitizer to skip &amp lt !-- node type X --&amp gt  in output
  (#1490583)

  - Fix charset encoding of message/rfc822 part bodies (#1490606)

  - Fix handling of message/rfc822 attachments on replies and forwards
  (#1490607)

  - Fix PDF support detection in Firefox &amp gt  19 (#1490610)

  - Fix path traversal vulnerability (CWE-22) in setting a skin (#1490620)
  [CVE-2015-8770] [bnc#962067]

  - Fix so drag-n-drop of text (e.g. recipient addresses) on compose page
  actually works (#1490619)

  - Fix .htaccess rewrite rules to not block .well-known URIs (#1490615)

  - Updated apache2 config");

  script_tag(name:"affected", value:"roundcubemail on openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:0214-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "openSUSE13.1")
{

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.0.8~2.27.1", rls:"openSUSE13.1"))) {
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
