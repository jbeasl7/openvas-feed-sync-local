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
  script_oid("1.3.6.1.4.1.25623.1.0.850802");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432", "CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for wireshark (SUSE-SU-2014:1221-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The wireshark package was upgraded to 1.10.10 from 1.8.x as 1.8 was
  discontinued.

  This update fixes vulnerabilities that could allow an attacker to crash
  Wireshark or make it become unresponsive by sending specific packets onto
  the network or have them loaded via a capture file while the dissectors
  are running. It also contains a number of other bug fixes.

  * RTP dissector crash. (wnpa-sec-2014-12 CVE-2014-6421 CVE-2014-6422)

  * MEGACO dissector infinite loop. (wnpa-sec-2014-13 CVE-2014-6423)

  * Netflow dissector crash. (wnpa-sec-2014-14 CVE-2014-6424)

  * RTSP dissector crash. (wnpa-sec-2014-17 CVE-2014-6427)

  * SES dissector crash. (wnpa-sec-2014-18 CVE-2014-6428)

  * Sniffer file parser crash. (wnpa-sec-2014-19 CVE-2014-6429
  CVE-2014-6430 CVE-2014-6431 CVE-2014-6432)

  * The Catapult DCT2000 and IrDA dissectors could underrun a buffer.
  (wnpa-sec-2014-08 CVE-2014-5161 CVE-2014-5162, bnc#889901)

  * The GSM Management dissector could crash. (wnpa-sec-2014-09
  CVE-2014-5163, bnc#889906)

  * The RLC dissector could crash. (wnpa-sec-2014-10 CVE-2014-5164,
  bnc#889900)

  * The ASN.1 BER dissector could crash. (wnpa-sec-2014-11
  CVE-2014-5165, bnc#889899)");

  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.9.html");

  script_tag(name:"affected", value:"wireshark on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1221-1");
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
  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.10~0.2.1", rls:"SLES11.0SP3"))) {
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
