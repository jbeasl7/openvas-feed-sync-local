# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2294.1");
  script_cve_id("CVE-2016-1245", "CVE-2017-5495");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-02 15:54:55 +0000 (Thu, 02 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2294-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2294-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172294-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034273");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003168.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the SUSE-SU-2017:2294-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides Quagga 1.1.1, which brings several fixes and enhancements.

Security issues fixed:

- CVE-2017-5495: Telnet 'vty' interface DoS due to unbounded memory allocation. (bsc#1021669)
- CVE-2016-1245: Stack overrun in IPv6 RA receive code. (bsc#1005258)

Bug fixes:

- Do not enable zebra's TCP interface (port 2600) to use default UNIX socket for communication
 between the daemons. (fate#323170)

Between 0.99.22.1 and 1.1.1 the following improvements have been implemented:

- Changed the default of 'link-detect' state, controlling whether zebra will respond to
 link-state events and consider an interface to be down when link is down. To retain the
 current behavior save your config before updating, otherwise remove the 'link-detect'
 flag from your config prior to updating. There is also a new global 'default link-detect
 (on<pipe>off)' flag to configure the global default.
- Greatly improved nexthop resolution for recursive routes.
- Event driven nexthop resolution for BGP.
- Route tags support.
- Transport of TE related metrics over OSPF, IS-IS.
- IPv6 Multipath for zebra and BGP.
- Multicast RIB support has been extended. It still is IPv4 only.
- RIP for IPv4 now supports equal-cost multipath (ECMP).
- route-maps have a new action 'set ipv6 next-hop peer-address'.
- route-maps have a new action 'set as-path prepend last-as'.
- 'next-hop-self all' to override nexthop on iBGP route reflector setups.
- New pimd daemon provides IPv4 PIM-SSM multicast routing.
- IPv6 address management has been improved regarding tentative addresses. This is visible in
 that a freshly configured address will not immediately be marked as usable.
- Recursive route support has been overhauled. Scripts parsing 'show ip route' output may need
 adaptation.
- A large amount of changes has been merged for ospf6d. Careful evaluation prior to deployment
 is recommended.
- Multiprotocol peerings over IPv6 now try to find a more appropriate IPv4 nexthop by looking at
 the interface.
- Relaxed bestpath criteria for multipath and improved display of multipath routes in 'show ip bgp'.
 Scripts parsing this output may need to be updated.
- Support for iBGP TTL security.");

  script_tag(name:"affected", value:"'quagga' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~17.3.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~17.3.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~17.3.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~17.3.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~17.3.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~17.3.3", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~17.3.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~17.3.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~17.3.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~17.3.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~17.3.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~17.3.3", rls:"SLES12.0SP3"))) {
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
