# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702893");
  script_cve_id("CVE-2013-2053", "CVE-2013-6466");
  script_tag(name:"creation_date", value:"2014-03-30 22:00:00 +0000 (Sun, 30 Mar 2014)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2893-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2893-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2893-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2893");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openswan' package(s) announced via the DSA-2893-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were fixed in Openswan, an IKE/IPsec implementation for Linux.

CVE-2013-2053

During an audit of Libreswan (with which Openswan shares some code), Florian Weimer found a remote buffer overflow in the atodn() function. This vulnerability can be triggered when Opportunistic Encryption (OE) is enabled and an attacker controls the PTR record of a peer IP address. Authentication is not needed to trigger the vulnerability.

CVE-2013-6466

Iustina Melinte found a vulnerability in Libreswan which also applies to the Openswan code. By carefully crafting IKEv2 packets, an attacker can make the pluto daemon dereference non-received IKEv2 payload, leading to the daemon crash. Authentication is not needed to trigger the vulnerability.

Patches were originally written to fix the vulnerabilities in Libreswan, and have been ported to Openswan by Paul Wouters from the Libreswan Project.

Since the Openswan package is not maintained anymore in the Debian distribution and is not available in testing and unstable suites, it is recommended for IKE/IPsec users to switch to a supported implementation like strongSwan.

For the oldstable distribution (squeeze), these problems have been fixed in version 2.6.28+dfsg-5+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 2.6.37-3.1.

We recommend that you upgrade your openswan packages.");

  script_tag(name:"affected", value:"'openswan' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"openswan", ver:"1:2.6.28+dfsg-5+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-dbg", ver:"1:2.6.28+dfsg-5+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-doc", ver:"1:2.6.28+dfsg-5+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-modules-dkms", ver:"1:2.6.28+dfsg-5+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-modules-source", ver:"1:2.6.28+dfsg-5+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"openswan", ver:"1:2.6.37-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-dbg", ver:"1:2.6.37-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-doc", ver:"1:2.6.37-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-modules-dkms", ver:"1:2.6.37-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openswan-modules-source", ver:"1:2.6.37-3+deb7u1", rls:"DEB7"))) {
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
