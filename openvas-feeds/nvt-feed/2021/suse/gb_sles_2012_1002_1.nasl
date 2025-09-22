# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1002.1");
  script_cve_id("CVE-2012-3570", "CVE-2012-3571", "CVE-2012-3954");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1002-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1002-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121002-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp' package(s) announced via the SUSE-SU-2012:1002-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides dhcp 4.2.4-p1, which fixes the dhcpv6 server crashing while accessing the lease on heap and provides the following additional fixes:

 *

 Security fixes:

 o Previously the server code was relaxed to allow packets with zero length client ids to be processed. Under some situations use of zero length client ids can cause the server to go into an infinite loop. As such ids are not valid according to RFC 2132 section 9.14 the server no longer accepts them. Client ids with a length of 1 are also invalid but the server still accepts them in order to minimize disruption. The restriction will likely be tightened in the future to disallow ids with a length of 1.
(ISC-Bugs #29851, CVE-2012-3571
> ) o When attempting to convert a DUID from a client id option into a hardware address handle unexpected client ids properly. (ISC-Bugs #29852, CVE-2012-3570
> ) o A pair of memory leaks were found and fixed.
(ISC-Bugs #30024, CVE-2012-3954
> )
 *

 Further upstream fixes:

 o Moved lease file check to a separate action so it is not used in restart -- it can fail when the daemon rewrites the lease causing a restart failure then. o Request dhcp6.sntp-servers in /etc/dhclient6.conf and forward to netconfig for processing. o Rotate the lease file when running in v6 mode. (ISC-Bugs #24887) o Fixed the code that checks if an address the server is planning to hand out is in a reserved range. This would appear as the server being out of addresses in pools with particular ranges. (ISC-Bugs #26498) o In the DDNS code handle error conditions more gracefully and add more logging code. The major change is to handle unexpected cancel events from the DNS client code. (ISC-Bugs #26287) o Tidy up the receive calls and eliminate the need for found_pkt. (ISC-Bugs
#25066) o Add support for Infiniband over sockets to the server and relay code. o Modify the code that determines if an outstanding DDNS request should be cancelled. This patch results in cancelling the outstanding request less often.
It fixes the problem caused by a client doing a release where the TXT and PTR records weren't removed from the DNS.
(ISC-BUGS #27858) o Remove outdated note in the description of the bootp keyword about the option not satisfying the requirement of failover peers for denying dynamic bootp clients. (ISC-bugs #28574) o Multiple items to clean up IPv6 address processing. When processing an IA that we've seen check to see if the addresses are usable (not in use by somebody else) before handing it out. When reading in leases from the file discard expired addresses. When picking an address for a client include the IA ID in addition to the client ID to generally pick different addresses for different IAs. (ISC-Bugs #23138, #27945,
#25586, #27684) o Remove unnecessary checks in the lease query code and clean up several compiler issues (some dereferences of NULL and treating an int as a boolean).
(ISC-Bugs ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dhcp' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.2.4.P1~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.2.4.P1~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.2.4.P1~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.2.4.P1~0.5.1", rls:"SLES11.0SP2"))) {
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
