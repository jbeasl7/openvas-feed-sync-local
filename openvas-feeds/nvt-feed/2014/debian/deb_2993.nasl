# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702993");
  script_cve_id("CVE-2014-5117");
  script_tag(name:"creation_date", value:"2014-07-30 22:00:00 +0000 (Wed, 30 Jul 2014)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2993-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2993-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2993-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2993");
  script_xref(name:"URL", value:"https://blog.torproject.org/blog/tor-security-advisory-relay-early-traffic-confirmation-attack");
  script_xref(name:"URL", value:"https://blog.torproject.org/blog/improving-tors-anonymity-changing-guard-parameters");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tor' package(s) announced via the DSA-2993-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in Tor, a connection-based low-latency anonymous communication system, resulting in information leaks.

Relay-early cells could be used by colluding relays on the network to tag user circuits and so deploy traffic confirmation attacks [CVE-2014-5117]. The updated version emits a warning and drops the circuit upon receiving inbound relay-early cells, preventing this specific kind of attack. Please consult the following advisory for more details about this issue:

[link moved to references]

A bug in the bounds-checking in the 32-bit curve25519-donna implementation could cause incorrect results on 32-bit implementations when certain malformed inputs were used along with a small class of private ntor keys. This flaw does not currently appear to allow an attacker to learn private keys or impersonate a Tor server, but it could provide a means to distinguish 32-bit Tor implementations from 64-bit Tor implementations.

The following additional security-related improvements have been implemented:

As a client, the new version will effectively stop using CREATE_FAST cells. While this adds computational load on the network, this approach can improve security on connections where Tor's circuit handshake is stronger than the available TLS connection security levels.

Prepare clients to use fewer entry guards by honoring the consensus parameters. The following article provides some background:

[link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 0.2.4.23-1~deb7u1.

For the testing distribution (jessie) and the unstable distribution (sid), these problems have been fixed in version 0.2.4.23-1.

For the experimental distribution, these problems have been fixed in version 0.2.5.6-alpha-1.

We recommend that you upgrade your tor packages.");

  script_tag(name:"affected", value:"'tor' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"tor", ver:"0.2.4.23-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.4.23-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.4.23-1~deb7u1", rls:"DEB7"))) {
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
