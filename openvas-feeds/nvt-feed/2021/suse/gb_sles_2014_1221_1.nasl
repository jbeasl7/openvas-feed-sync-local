# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1221.1");
  script_cve_id("CVE-2014-5161", "CVE-2014-5162", "CVE-2014-5163", "CVE-2014-5164", "CVE-2014-5165", "CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1221-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1221-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141221-1/");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.9.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2014:1221-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The wireshark package was upgraded to 1.10.10 from 1.8.x as 1.8 was discontinued.

This update fixes vulnerabilities that could allow an attacker to crash Wireshark or make it become unresponsive by sending specific packets onto the network or have them loaded via a capture file while the dissectors are running. It also contains a number of other bug fixes.

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
 CVE-2014-5165, bnc#889899)

Further bug fixes as listed in:
[link moved to references] and [link moved to references] .
Security Issues:
 * CVE-2014-5161
 * CVE-2014-5162
 * CVE-2014-5163
 * CVE-2014-5164
 * CVE-2014-5165
 * CVE-2014-6421
 * CVE-2014-6422
 * CVE-2014-6423
 * CVE-2014-6424
 * CVE-2014-6427
 * CVE-2014-6428
 * CVE-2014-6429
 * CVE-2014-6430
 * CVE-2014-6431
 * CVE-2014-6432");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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
