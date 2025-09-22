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
  script_oid("1.3.6.1.4.1.25623.1.0.850764");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-3638", "CVE-2014-3639");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for dbus-1 (SUSE-SU-2014:1146-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus-1'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various denial of service issues were fixed in the DBUS service.

  * CVE-2014-3638: dbus-daemon tracks whether method call messages
  expect a reply, so that unsolicited replies can be dropped. As
  currently implemented, if there are n parallel method calls in
  progress, each method reply takes O(n) CPU time. A malicious user
  could exploit this by opening the maximum allowed number of parallel
  connections and sending the maximum number of parallel method calls
  on each one, causing subsequent method calls to be unreasonably
  slow, a denial of service.

  * CVE-2014-3639: dbus-daemon allows a small number of 'incomplete'
  connections (64 by default) whose identity has not yet been
  confirmed. When this limit has been reached, subsequent connections
  are dropped. Alban's testing indicates that one malicious process
  that makes repeated connection attempts, but never completes the
  authentication handshake and instead waits for dbus-daemon to time
  out and disconnect it, can cause the majority of legitimate
  connection attempts to fail.");

  script_tag(name:"affected", value:"dbus-1 on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1146-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.2.10~3.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.2.10~3.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-32bit", rpm:"dbus-1-32bit~1.2.10~3.31.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x86", rpm:"dbus-1-x86~1.2.10~3.31.1", rls:"SLES11.0SP3"))) {
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
