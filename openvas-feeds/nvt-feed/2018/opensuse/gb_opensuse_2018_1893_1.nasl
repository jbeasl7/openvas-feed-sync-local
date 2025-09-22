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
  script_oid("1.3.6.1.4.1.25623.1.0.852027");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-1071", "CVE-2018-1083", "CVE-2018-1100");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 07:15:00 +0000 (Tue, 01 Dec 2020)");
  script_tag(name:"creation_date", value:"2018-10-26 06:35:28 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for zsh (openSUSE-SU-2018:1893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:1893-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-07/msg00000.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh'
  package(s) announced via the openSUSE-SU-2018:1893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zsh to version 5.5 fixes the following issues:

  Security issues fixed:

  - CVE-2018-1100: Fixes a buffer overflow in utils.c:checkmailpath() that
  can lead to local arbitrary code execution (bsc#1089030)

  - CVE-2018-1071: Fixed a stack-based buffer overflow in exec.c:hashcmd()
  (bsc#1084656)

  - CVE-2018-1083: Fixed a stack-based buffer overflow in
  gen_matches_files() at compctl.c (bsc#1087026)

  Non-security issues fixed:

  - The effect of the NO_INTERACTIVE_COMMENTS option extends into $(...) and
  `...` command substitutions when used on the command line.

  - The 'exec' and 'command' precommand modifiers, and options to them, are
  now parsed after parameter expansion.

  - Functions executed by ZLE widgets no longer have their standard input
  closed, but redirected from /dev/null instead.

  - There is an option WARN_NESTED_VAR, a companion to the existing
  WARN_CREATE_GLOBAL that causes a warning if a function updates a
  variable from an enclosing scope without using typeset -g.

  - zmodload now has an option -s to be silent on a failure to find a module
  but still print other errors.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-699=1");

  script_tag(name:"affected", value:"zsh on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"zsh", rpm:"zsh~5.5~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zsh-debuginfo", rpm:"zsh-debuginfo~5.5~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zsh-debugsource", rpm:"zsh-debugsource~5.5~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zsh-htmldoc", rpm:"zsh-htmldoc~5.5~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
