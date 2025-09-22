# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704133");
  script_cve_id("CVE-2017-3144", "CVE-2018-5732", "CVE-2018-5733");
  script_tag(name:"creation_date", value:"2018-03-06 23:00:00 +0000 (Tue, 06 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-07 21:08:53 +0000 (Thu, 07 Feb 2019)");

  script_name("Debian: Security Advisory (DSA-4133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4133-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4133-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4133");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/isc-dhcp");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'isc-dhcp' package(s) announced via the DSA-4133-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the ISC DHCP client, relay and server. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2017-3144

It was discovered that the DHCP server does not properly clean up closed OMAPI connections, which can lead to exhaustion of the pool of socket descriptors available to the DHCP server, resulting in denial of service.

CVE-2018-5732

Felix Wilhelm of the Google Security Team discovered that the DHCP client is prone to an out-of-bound memory access vulnerability when processing specially constructed DHCP options responses, resulting in potential execution of arbitrary code by a malicious DHCP server.

CVE-2018-5733

Felix Wilhelm of the Google Security Team discovered that the DHCP server does not properly handle reference counting when processing client requests. A malicious client can take advantage of this flaw to cause a denial of service (dhcpd crash) by sending large amounts of traffic.

For the oldstable distribution (jessie), these problems have been fixed in version 4.3.1-6+deb8u3.

For the stable distribution (stretch), these problems have been fixed in version 4.3.5-3+deb9u1.

We recommend that you upgrade your isc-dhcp packages.

For the detailed security status of isc-dhcp please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'isc-dhcp' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-dbg", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-udeb", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-dbg", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay-dbg", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-dbg", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.3.1-6+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-ddns", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-udeb", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.3.5-3+deb9u1", rls:"DEB9"))) {
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
