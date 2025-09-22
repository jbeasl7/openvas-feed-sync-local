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
  script_oid("1.3.6.1.4.1.25623.1.0.850995");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-10-16 16:23:14 +0200 (Fri, 16 Oct 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-1931", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:43:11 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for java-1_7_1-ibm (SUSE-SU-2015:1331-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java was updated to 7.1-3.10 to fix several security issues.

  The following vulnerabilities were fixed:

  * CVE-2015-1931: IBM Java Security Components store plain text data in
  memory dumps, which could allow a local attacker to obtain information
  to aid in further attacks against the system.

  * CVE-2015-2590: Easily exploitable vulnerability in the Libraries
  component allowed successful unauthenticated network attacks via
  multiple protocols. Successful attack of this vulnerability could have
  resulted in unauthorized Operating System takeover including arbitrary
  code execution.

  * CVE-2015-2601: Easily exploitable vulnerability in the JCE component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2613: Easily exploitable vulnerability in the JCE component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java SE, Java SE Embedded
  accessible data.

  * CVE-2015-2619: Easily exploitable vulnerability in the 2D component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2621: Easily exploitable vulnerability in the JMX component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2625: Very difficult to exploit vulnerability in the JSSE
  component allowed successful unauthenticated network attacks via
  SSL/TLS. Successful attack of this vulnerability could have resulted in
  unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2632: Easily exploitable vulnerability in the 2D component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2637: Easily exploitable vulnerability in the 2D component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2638: Easily exploitab ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"java-1_7_1-ibm on SUSE Linux Enterprise Server 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:1331-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr3.10~14.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr3.10~14.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr3.10~14.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr3.10~14.1", rls:"SLES12.0SP0"))) {
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
