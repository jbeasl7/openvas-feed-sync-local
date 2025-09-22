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
  script_oid("1.3.6.1.4.1.25623.1.0.851371");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2016-08-02 10:57:05 +0530 (Tue, 02 Aug 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for dropbear (openSUSE-SU-2016:1891-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dropbear'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dropbear fixes four security issues (bnc#990363):

  - A format string injection vulnerability allowed remotes attacker to run
  arbitrary code as root if specific usernames including '%' symbols could
  be created on the target system. If a dbclient user can control
  usernames or host arguments, or untrusted input is processed,
  potentially arbitrary code could have been executed as the dbclient user.

  - When importing malicious OpenSSH key files via dropbearconvert,
  arbitrary code could have been executed as the local dropbearconvert user

  - If particular -m or -c arguments were provided, as used in scripts,
  dbclient could have executed arbitrary code

  - dbclient or dropbear server could have exposed process memory to the
  running user if compiled with DEBUG_TRACE and running with -v

  Dropbear was updated to the upstream 2016.74 release, including fixes for
  the following upstream issues:

  - Port forwarding failure when connecting to domains that have both IPv4
  and IPv6 addresses

  - 100% CPU use while waiting for rekey to complete

  - Fix crash when fallback initshells() is used scp failing when the local
  user doesn't exist

  The following upstream improvements are included:

  - Support syslog in dbclient, option -o usesyslog=yes

  - Kill a proxycommand when dbclient exits

  - Option to exit when a TCP forward fails

  - Allow specifying commands eg 'dropbearmulti dbclient ...' instead of
  symlinks");

  script_tag(name:"affected", value:"dropbear on openSUSE Leap 42.1, openSUSE 13.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:1891-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2")
{

  if(!isnull(res = isrpmvuln(pkg:"dropbear", rpm:"dropbear~2016.74~2.6.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dropbear-debuginfo", rpm:"dropbear-debuginfo~2016.74~2.6.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dropbear-debugsource", rpm:"dropbear-debugsource~2016.74~2.6.1", rls:"openSUSE13.2"))) {
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
