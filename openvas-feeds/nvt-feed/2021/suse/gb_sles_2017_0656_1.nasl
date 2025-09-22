# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0656.1");
  script_cve_id("CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7931", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-01 22:55:51 +0000 (Wed, 01 Feb 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0656-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0656-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170656-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020940");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-March/002691.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the SUSE-SU-2017:0656-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump fixes the following issues:

Security issues fixed (bsc#1020940):
- CVE-2016-7922: Corrected buffer overflow in AH parser print-ah.c:ah_print().
- CVE-2016-7923: Corrected buffer overflow in ARP parser print-arp.c:arp_print().
- CVE-2016-7925: Corrected buffer overflow in compressed SLIP parser print-sl.c:sl_if_print().
- CVE-2016-7926: Corrected buffer overflow in the Ethernet parser print-ether.c:ethertype_print().
- CVE-2016-7927: Corrected buffer overflow in the IEEE 802.11 parser print-802_11.c:ieee802_11_radio_print().
- CVE-2016-7928: Corrected buffer overflow in the IPComp parser print-ipcomp.c:ipcomp_print().
- CVE-2016-7931: Corrected buffer overflow in the MPLS parser print-mpls.c:mpls_print().
- CVE-2016-7936: Corrected buffer overflow in the UDP parser print-udp.c:udp_print().
- CVE-2016-7934,CVE-2016-7935,CVE-2016-7937: Corrected segmentation faults in function udp_print().
- CVE-2016-7939: Corrected buffer overflows in GRE parser print-gre.c:(multiple functions).
- CVE-2016-7940: Corrected buffer overflows in STP parser print-stp.c:(multiple functions).
- CVE-2016-7973: Corrected buffer overflow in AppleTalk parser print-atalk.c.
- CVE-2016-7974: Corrected buffer overflow in IP parser print-ip.c:(multiple functions).
- CVE-2016-7975: Corrected buffer overflow in TCP parser print-tcp.c:tcp_print().
- CVE-2016-7983,CVE-2016-7984: Corrected buffer overflow in TFTP parser print-tftp.c:tftp_print().
- CVE-2016-7992: Corrected buffer overflow in Classical IP over ATM parser print-cip.c.
- CVE-2016-7993: Corrected buffer overflow in multiple protocol parsers (DNS, DVMRP, HSRP, etc.).
- CVE-2016-8574: Corrected buffer overflow in FRF.15 parser print-fr.c:frf15_print().
- CVE-2017-5202: Corrected buffer overflow in ISO CLNS parser print-isoclns.c:clnp_print().
- CVE-2017-5203: Corrected buffer overflow in BOOTP parser print-bootp.c:bootp_print().
- CVE-2017-5204: Corrected buffer overflow in IPv6 parser print-ip6.c:ip6_print().
- CVE-2017-5483: Corrected buffer overflow in SNMP parser print-snmp.c:asn1_parse().
- CVE-2017-5484: Corrected buffer overflow in ATM parser print-atm.c:sig_print().
- CVE-2017-5485: Corrected buffer overflow in ISO CLNS parser addrtoname.c:lookup_nsap().
- CVE-2017-5486: Corrected buffer overflow in ISO CLNS parser print-isoclns.c:clnp_print().");

  script_tag(name:"affected", value:"'tcpdump' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~3.9.8~1.29.1", rls:"SLES11.0SP4"))) {
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
