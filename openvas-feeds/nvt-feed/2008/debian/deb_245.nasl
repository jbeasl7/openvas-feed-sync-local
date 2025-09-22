# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53321");
  script_cve_id("CVE-2003-0039");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-245)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-245");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-245");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-245");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dhcp3' package(s) announced via the DSA-245 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Lohoff discovered a bug in the dhcrelay causing it to send a continuing packet storm towards the configured DHCP server(s) in case of a malicious BOOTP packet, such as sent from buggy Cisco switches.

When the dhcp-relay receives a BOOTP request it forwards the request to the DHCP server using the broadcast MAC address ff:ff:ff:ff:ff:ff which causes the network interface to reflect the packet back into the socket. To prevent loops the dhcrelay checks whether the relay-address is its own, in which case the packet would be dropped. In combination with a missing upper boundary for the hop counter an attacker can force the dhcp-relay to send a continuing packet storm towards the configured dhcp server(s).

This patch introduces a new command line switch -c maxcount and people are advised to start the dhcp-relay with dhcrelay -c 10 or a smaller number, which will only create that many packets.

The dhcrelay program from the 'dhcp' package does not seem to be affected since DHCP packets are dropped if they were apparently relayed already.

For the stable distribution (woody) this problem has been fixed in version 3.0+3.0.1rc9-2.2.

The old stable distribution (potato) does not contain dhcp3 packages.

For the unstable distribution (sid) this problem has been fixed in version 1.1.2-1.

We recommend that you upgrade your dhcp3 package when you are using the dhcrelay server.");

  script_tag(name:"affected", value:"'dhcp3' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.0+3.0.1rc9-2.2", rls:"DEB3.0"))) {
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
