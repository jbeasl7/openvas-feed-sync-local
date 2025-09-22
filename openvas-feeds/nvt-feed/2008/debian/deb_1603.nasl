# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61249");
  script_cve_id("CVE-2008-1447");
  script_tag(name:"creation_date", value:"2008-07-15 00:29:31 +0000 (Tue, 15 Jul 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2008-07-09 15:22:00 +0000 (Wed, 09 Jul 2008)");

  script_name("Debian: Security Advisory (DSA-1603-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1603-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1603-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1603");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-1603-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Kaminsky discovered that properties inherent to the DNS protocol lead to practical DNS cache poisoning attacks. Among other things, successful attacks can lead to misdirected web traffic and email rerouting.

This update changes Debian's BIND 9 packages to implement the recommended countermeasure: UDP query source port randomization. This change increases the size of the space from which an attacker has to guess values in a backwards-compatible fashion and makes successful attacks significantly more difficult.

Note that this security update changes BIND network behavior in a fundamental way, and the following steps are recommended to ensure a smooth upgrade.

1. Make sure that your network configuration is compatible with source port randomization. If you guard your resolver with a stateless packet filter, you may need to make sure that no non-DNS services listen on the 1024--65535 UDP port range and open it at the packet filter. For instance, packet filters based on etch's Linux 2.6.18 kernel only support stateless filtering of IPv6 packets, and therefore pose this additional difficulty. (If you use IPv4 with iptables and ESTABLISHED rules, networking changes are likely not required.)

2. Install the BIND 9 upgrade, using 'apt-get update' followed by 'apt-get install bind9'. Verify that the named process has been restarted and answers recursive queries. (If all queries result in timeouts, this indicates that networking changes are necessary, see the first step.)

3. Verify that source port randomization is active. Check that the /var/log/daemon.log file does not contain messages of the following form

named[6106]: /etc/bind/named.conf.options:28: using specific query-source port suppresses port randomization and can be insecure.

right after the 'listening on IPv6 interface' and 'listening on IPv4 interface' messages logged by BIND upon startup. If these messages are present, you should remove the indicated lines from the configuration, or replace the port numbers contained within them with '*' sign (e.g., replace 'port 53' with 'port *').

For additional certainty, use tcpdump or some other network monitoring tool to check for varying UDP source ports. If there is a NAT device in front of your resolver, make sure that it does not defeat the effect of source port randomization.

4. If you cannot activate source port randomization, consider configuring BIND 9 to forward queries to a resolver which can, possibly over a VPN such as OpenVPN to create the necessary trusted network link. (Use BIND's forward-only mode in this case.)

Other caching resolvers distributed by Debian (PowerDNS, MaraDNS, Unbound) already employ source port randomization, and no updated packages are needed. BIND 9.5 up to and including version 1:9.5.0.dfsg-4 only implements a weak form of source port randomization and needs to be updated as well. For information on BIND 8, see DSA-1604-1, and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-doc", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bind9-host", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dnsutils", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind-dev", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbind9-0", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdns22", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisc11", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccc0", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libisccfg1", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblwres9", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lwresd", ver:"1:9.3.4-2etch3", rls:"DEB4"))) {
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
