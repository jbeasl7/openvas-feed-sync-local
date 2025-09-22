# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850572");
  script_version("2021-10-15T11:02:56+0000");
  script_tag(name:"last_modification", value:"2021-10-15 11:02:56 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2014-03-12 09:29:13 +0530 (Wed, 12 Mar 2014)");
  script_cve_id("CVE-2014-2029");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-10 11:51:00 +0000 (Tue, 10 Oct 2017)");
  script_name("openSUSE: Security Advisory for percona-toolkit, xtrabackup (openSUSE-SU-2014:0333-1)");

  script_tag(name:"affected", value:"percona-toolkit, xtrabackup on openSUSE 13.1");

  script_tag(name:"insight", value:"percona-toolkit and xtrabackup were updated:

  - disable automatic version check for all tools
  [bnc#864194] Prevents transmission of version information
  to an external host in the default configuration.
  CVE-2014-2029 Can be used by owner of a Percona Server
  (or an attacker who can control this destination for the
  client) to collect arbitrary MySQL configuration
  parameters and execute commands (with -v). Now the
  version check needs to be requested via command line or
  global/tool specific/user configuration. (--version-check)

  - added /etc/percona-toolkit/percona-toolkit.conf
  configuration directory and template configuration file");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"openSUSE-SU", value:"2014:0333-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'percona-toolkit, xtrabackup'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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
  if(!isnull(res = isrpmvuln(pkg:"xtrabackup", rpm:"xtrabackup~2.1.7~13.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtrabackup-debuginfo", rpm:"xtrabackup-debuginfo~2.1.7~13.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtrabackup-debugsource", rpm:"xtrabackup-debugsource~2.1.7~13.2", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"percona-toolkit", rpm:"percona-toolkit~2.2.7~2.10.1", rls:"openSUSE13.1"))) {
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
