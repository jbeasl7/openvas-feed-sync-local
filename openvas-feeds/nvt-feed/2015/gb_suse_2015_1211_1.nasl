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
  script_oid("1.3.6.1.4.1.25623.1.0.850845");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-10-15 12:12:54 +0200 (Thu, 15 Oct 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0578", "CVE-2015-3114", "CVE-2015-3115", "CVE-2015-3116",
                "CVE-2015-3117", "CVE-2015-3118", "CVE-2015-3119", "CVE-2015-3120",
                "CVE-2015-3121", "CVE-2015-3122", "CVE-2015-3123", "CVE-2015-3124",
                "CVE-2015-3125", "CVE-2015-3126", "CVE-2015-3127", "CVE-2015-3128",
                "CVE-2015-3129", "CVE-2015-3130", "CVE-2015-3131", "CVE-2015-3132",
                "CVE-2015-3133", "CVE-2015-3134", "CVE-2015-3135", "CVE-2015-3136",
                "CVE-2015-3137", "CVE-2015-4428", "CVE-2015-4429", "CVE-2015-4430",
                "CVE-2015-4431", "CVE-2015-4432", "CVE-2015-4433", "CVE-2015-5116",
                "CVE-2015-5117", "CVE-2015-5118", "CVE-2015-5119");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:24:10 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for flash-player (SUSE-SU-2015:1211-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"flash-player was updated to fix 35 security issues.

  These security issues were fixed:

  - CVE-2015-3135, CVE-2015-4432, CVE-2015-5118: Heap buffer overflow
  vulnerabilities that could lead to code execution (bsc#937339).

  - CVE-2015-3117, CVE-2015-3123, CVE-2015-3130, CVE-2015-3133,
  CVE-2015-3134, CVE-2015-4431: Memory corruption vulnerabilities that
  could lead to code execution (bsc#937339).

  - CVE-2015-3126, CVE-2015-4429: Null pointer dereference issues
  (bsc#937339).

  - CVE-2015-3114: A security bypass vulnerability that could lead to
  information disclosure (bsc#937339).

  - CVE-2015-3119, CVE-2015-3120, CVE-2015-3121, CVE-2015-3122,
  CVE-2015-4433: Type confusion vulnerabilities that could lead to code
  execution (bsc#937339).

  - CVE-2015-3118, CVE-2015-3124, CVE-2015-5117, CVE-2015-3127,
  CVE-2015-3128, CVE-2015-3129, CVE-2015-3131, CVE-2015-3132,
  CVE-2015-3136, CVE-2015-3137, CVE-2015-4428, CVE-2015-4430,
  CVE-2015-5119: Use-after-free vulnerabilities that could lead to code
  execution (bsc#937339).

  - CVE-2014-0578, CVE-2015-3115, CVE-2015-3116, CVE-2015-3125,
  CVE-2015-5116: Vulnerabilities that could be exploited to bypass the
  same-origin-policy and lead to information disclosure (bsc#937339).");

  script_tag(name:"affected", value:"flash-player on SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:1211-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~11.2.202.481~93.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-gnome", rpm:"flash-player-gnome~11.2.202.481~93.1", rls:"SLED12.0SP0"))) {
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
