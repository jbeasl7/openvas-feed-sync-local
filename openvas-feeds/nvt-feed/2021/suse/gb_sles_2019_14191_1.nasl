# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14191.1");
  script_cve_id("CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13041", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13051", "CVE-2017-13053", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13725", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-15166");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-07 17:37:15 +0000 (Mon, 07 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14191-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14191-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914191-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153332");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the SUSE-SU-2019:14191-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump fixes the following issues:

Security issues fixed:

- CVE-2017-12995: Fixed an infinite loop in the DNS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12893: Fixed a buffer over-read in the SMB/CIFS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12894: Fixed a buffer over-read in several protocol parsers that allowed remote DoS (bsc#1057247).
- CVE-2017-12896: Fixed a buffer over-read in the ISAKMP parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12897: Fixed a buffer over-read in the ISO CLNS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12898: Fixed a buffer over-read in the NFS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12899: Fixed a buffer over-read in the DECnet parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12900: Fixed a buffer over-read in the in several protocol parsers that allowed remote DoS (bsc#1057247).
- CVE-2017-12901: Fixed a buffer over-read in the EIGRP parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12902: Fixed a buffer over-read in the Zephyr parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12985: Fixed a buffer over-read in the IPv6 parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12986: Fixed a buffer over-read in the IPv6 routing header parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12987: Fixed a buffer over-read in the 802.11 parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12988: Fixed a buffer over-read in the telnet parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12991: Fixed a buffer over-read in the BGP parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12992: Fixed a buffer over-read in the RIPng parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12993: Fixed a buffer over-read in the Juniper protocols parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12996: Fixed a buffer over-read in the PIMv2 parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12998: Fixed a buffer over-read in the IS-IS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-12999: Fixed a buffer over-read in the IS-IS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13001: Fixed a buffer over-read in the NFS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13002: Fixed a buffer over-read in the AODV parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13003: Fixed a buffer over-read in the LMP parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13004: Fixed a buffer over-read in the Juniper protocols parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13005: Fixed a buffer over-read in the NFS parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13006: Fixed a buffer over-read in the L2TP parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13008: Fixed a buffer over-read in the IEEE 802.11 parser that allowed remote DoS (bsc#1057247).
- CVE-2017-13009: Fixed a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tcpdump' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~3.9.8~1.30.13.1", rls:"SLES11.0SP4"))) {
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
