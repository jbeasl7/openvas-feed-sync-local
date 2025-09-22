# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703442");
  script_cve_id("CVE-2015-8605");
  script_tag(name:"creation_date", value:"2016-01-12 23:00:00 +0000 (Tue, 12 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-19 17:07:20 +0000 (Tue, 19 Jan 2016)");

  script_name("Debian: Security Advisory (DSA-3442-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3442-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3442-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3442");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'isc-dhcp' package(s) announced via the DSA-3442-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a maliciously crafted packet can crash any of the isc-dhcp applications. This includes the DHCP client, relay, and server application. Only IPv4 setups are affected.

For the oldstable distribution (wheezy), this problem has been fixed in version 4.2.2.dfsg.1-5+deb70u8.

For the stable distribution (jessie), this problem has been fixed in version 4.3.1-6+deb8u2.

For the testing (stretch) and unstable (sid) distributions, this problem will be fixed soon.

We recommend that you upgrade your isc-dhcp packages.");

  script_tag(name:"affected", value:"'isc-dhcp' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-dbg", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-udeb", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay-dbg", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-dbg", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.2.2.dfsg.1-5+deb70u8", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-dbg", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client-udeb", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-dbg", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-relay-dbg", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-dbg", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.3.1-6+deb8u2", rls:"DEB8"))) {
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
