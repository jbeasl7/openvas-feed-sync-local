# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2854.1");
  script_cve_id("CVE-2017-11108", "CVE-2017-11541", "CVE-2017-11542", "CVE-2017-11543", "CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12895", "CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989", "CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13007", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041", "CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045", "CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053", "CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-16 10:31:19 +0000 (Sat, 16 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2854-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2854-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172854-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057247");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-October/003355.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the SUSE-SU-2017:2854-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump to version 4.9.2 fixes several issues.

These security issues were fixed:

- CVE-2017-11108: Prevent remote attackers to cause DoS (heap-based buffer over-read and application crash) via crafted packet data. The crash occurred in the EXTRACT_16BITS function, called from the stp_print function for the Spanning Tree Protocol (bsc#1047873, bsc#1057247).
- CVE-2017-11543: Prevent buffer overflow in the sliplink_print function in print-sl.c that allowed remote DoS (bsc#1057247).
- CVE-2017-13011: Prevent buffer overflow in bittok2str_internal() that allowed remote DoS (bsc#1057247)
- CVE-2017-12989: Prevent infinite loop in the RESP parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12990: Prevent infinite loop in the ISAKMP parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12995: Prevent infinite loop in the DNS parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12997: Prevent infinite loop in the LLDP parser that allowed remote DoS (bsc#1057247)
- CVE-2017-11541: Prevent heap-based buffer over-read in the lldp_print function in print-lldp.c, related to util-print.c that allowed remote DoS (bsc#1057247).
- CVE-2017-11542: Prevent heap-based buffer over-read in the pimv1_print function in print-pim.c that allowed remote DoS (bsc#1057247).
- CVE-2017-12893: Prevent buffer over-read in the SMB/CIFS parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12894: Prevent buffer over-read in several protocol parsers that allowed remote DoS (bsc#1057247)
- CVE-2017-12895: Prevent buffer over-read in the ICMP parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12896: Prevent buffer over-read in the ISAKMP parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12897: Prevent buffer over-read in the ISO CLNS parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12898: Prevent buffer over-read in the NFS parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12899: Prevent buffer over-read in the DECnet parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12900: Prevent buffer over-read in the in several protocol parsers that allowed remote DoS (bsc#1057247)
- CVE-2017-12901: Prevent buffer over-read in the EIGRP parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12902: Prevent buffer over-read in the Zephyr parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12985: Prevent buffer over-read in the IPv6 parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12986: Prevent buffer over-read in the IPv6 routing header parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12987: Prevent buffer over-read in the 802.11 parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12988: Prevent buffer over-read in the telnet parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12991: Prevent buffer over-read in the BGP parser that allowed remote DoS (bsc#1057247)
- CVE-2017-12992: Prevent buffer over-read in the RIPng parser that ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tcpdump' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.2~14.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.2~14.5.1", rls:"SLES12.0SP3"))) {
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
