# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0322.1");
  script_cve_id("CVE-2013-1572", "CVE-2013-1573", "CVE-2013-1574", "CVE-2013-1575", "CVE-2013-1576", "CVE-2013-1577", "CVE-2013-1578", "CVE-2013-1579", "CVE-2013-1580", "CVE-2013-1581", "CVE-2013-1582", "CVE-2013-1583", "CVE-2013-1584", "CVE-2013-1585", "CVE-2013-1586", "CVE-2013-1587", "CVE-2013-1588", "CVE-2013-1589", "CVE-2013-1590");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0322-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130322-1/");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.5.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2013:0322-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"wireshark was updated to 1.8.5 (bnc#801131), fixing bugs and security issues:

The following vulnerabilities have been fixed:

 * Infinite and large loops in the Bluetooth HCI, CSN.1,
DCP-ETSI DOCSIS CM-STAUS, IEEE 802.3 Slow Protocols, MPLS,
R3, RTPS, SDP, and SIP dissectors wnpa-sec-2013-01 CVE-2013-1572 CVE-2013-1573 CVE-2013-1574 CVE-2013-1575 CVE-2013-1576 CVE-2013-1577 CVE-2013-1578 CVE-2013-1579 CVE-2013-1580 CVE-2013-1581
 * The CLNP dissector could crash wnpa-sec-2013-02 CVE-2013-1582
 * The DTN dissector could crash wnpa-sec-2013-03 CVE-2013-1583 CVE-2013-1584
 * The MS-MMC dissector (and possibly others) could crash wnpa-sec-2013-04 CVE-2013-1585
 * The DTLS dissector could crash wnpa-sec-2013-05 CVE-2013-1586
 * The ROHC dissector could crash wnpa-sec-2013-06 CVE-2013-1587
 * The DCP-ETSI dissector could corrupt memory wnpa-sec-2013-07 CVE-2013-1588
 * The Wireshark dissection engine could crash wnpa-sec-2013-08 CVE-2013-1589
 * The NTLMSSP dissector could overflow a buffer wnpa-sec-2013-09 CVE-2013-1590

Further bug fixes and updated protocol support as listed in:

[link moved to references]
>");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.6.13~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.6.13~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.5~0.2.1", rls:"SLES11.0SP2"))) {
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
