# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-10/msg00031.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831471");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"MDVA", value:"2011:058");
  script_name("Mandriva Update for timezone MDVA-2011:058 (timezone)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'timezone'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1)");
  script_tag(name:"affected", value:"timezone on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Timezone is a package that contains data files with rules for various
  timezones around the world. In autumn 2011 Russia, Belarus and Ukraine
  drop transition on winter time. Palestine suspends DST during Ramadan
  in 2011. Gaza and West Bank split in 2011.  West Bank is tracked in
  the timezone Asia/Hebron. This package fix this. Also we fix some
  error on UK and China timezone definition.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
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

if(release == "MNDK_mes5") {
  if(!isnull(res = isrpmvuln(pkg:"timezone", rpm:"timezone~2011k~0.1mdvmes5.2", rls:"MNDK_mes5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"timezone-java", rpm:"timezone-java~2011k~0.1mdvmes5.2", rls:"MNDK_mes5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MNDK_2010.1") {
  if(!isnull(res = isrpmvuln(pkg:"timezone", rpm:"timezone~2011k~1.1mdv2010.2", rls:"MNDK_2010.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"timezone-java", rpm:"timezone-java~2011k~1.1mdv2010.2", rls:"MNDK_2010.1"))) {
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
