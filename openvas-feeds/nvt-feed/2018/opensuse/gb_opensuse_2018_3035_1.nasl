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
  script_oid("1.3.6.1.4.1.25623.1.0.851925");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-10-06 08:17:09 +0200 (Sat, 06 Oct 2018)");
  script_cve_id("CVE-2018-16976");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for gitolite (openSUSE-SU-2018:3035-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gitolite'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gitolite fixes the following issues:

  Gitolite was updated to 3.6.9:

  - CVE-2018-16976: prevent racy access to repos in process of migration to
  gitolite (boo#1108272)

  - 'info' learns new '-p' option to show only physical repos (as opposed to
  wild repos)

  The update to 3.6.8 contains:

  - fix bug when deleting *all* hooks for a repo

  - allow trailing slashes in repo names

  - make pre-receive hook driver bail on non-zero exit of a pre-receive hook

  - allow templates in gitolite.conf (new feature)

  - various optimiations

  The update to 3.6.7 contains:

  - allow repo-specific hooks to be organised into subdirectories, and allow
  the multi-hook driver to be placed in some other location of your choice

  - allow simple test code to be embedded within the gitolite.conf file  see
  contrib/utils/testconf for how. (This goes on the client side, not on
  the server)

  - allow syslog 'facility' to be changed, from the default of 'local0'

  - allow syslog 'facility' to be changed, from the default of replaced with
  a space separated list of members

  The update to 3.6.6 contains:

  - simple but important fix for a future perl deprecation (perl will be
  removing '.' from @INC in 5.24)

  - 'perms' now requires a '-c' to activate batch mode (should not affect
  interactive use but check your scripts perhaps?)

  - gitolite setup now accepts a '-m' option to supply a custom message
  (useful when it is used by a script)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1118=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1118=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1118=1");

  script_tag(name:"affected", value:"gitolite on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:3035-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00010.html");
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
  if(!isnull(res = isrpmvuln(pkg:"gitolite", rpm:"gitolite~3.6.9~4.3.1", rls:"openSUSELeap42.3"))) {
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
