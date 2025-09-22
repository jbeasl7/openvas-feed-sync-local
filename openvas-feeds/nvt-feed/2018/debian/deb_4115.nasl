# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704115");
  script_cve_id("CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"creation_date", value:"2018-02-14 23:00:00 +0000 (Wed, 14 Feb 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-14 18:39:35 +0000 (Wed, 14 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-4115-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4115-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4115-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4115");
  script_xref(name:"URL", value:"https://www.quagga.net/security/Quagga-2018-0543.txt");
  script_xref(name:"URL", value:"https://www.quagga.net/security/Quagga-2018-1114.txt");
  script_xref(name:"URL", value:"https://www.quagga.net/security/Quagga-2018-1550.txt");
  script_xref(name:"URL", value:"https://www.quagga.net/security/Quagga-2018-1975.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/quagga");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'quagga' package(s) announced via the DSA-4115-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Quagga, a routing daemon. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2018-5378

It was discovered that the Quagga BGP daemon, bgpd, does not properly bounds check data sent with a NOTIFY to a peer, if an attribute length is invalid. A configured BGP peer can take advantage of this bug to read memory from the bgpd process or cause a denial of service (daemon crash).

[link moved to references]

CVE-2018-5379

It was discovered that the Quagga BGP daemon, bgpd, can double-free memory when processing certain forms of UPDATE message, containing cluster-list and/or unknown attributes, resulting in a denial of service (bgpd daemon crash).

[link moved to references]

CVE-2018-5380

It was discovered that the Quagga BGP daemon, bgpd, does not properly handle internal BGP code-to-string conversion tables.

[link moved to references]

CVE-2018-5381

It was discovered that the Quagga BGP daemon, bgpd, can enter an infinite loop if sent an invalid OPEN message by a configured peer. A configured peer can take advantage of this flaw to cause a denial of service (bgpd daemon not responding to any other events, BGP sessions will drop and not be reestablished, unresponsive CLI interface).

[link moved to references]

For the oldstable distribution (jessie), these problems have been fixed in version 0.99.23.1-1+deb8u5.

For the stable distribution (stretch), these problems have been fixed in version 1.1.1-3+deb9u2.

We recommend that you upgrade your quagga packages.

For the detailed security status of quagga please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'quagga' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"0.99.23.1-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-dbg", ver:"0.99.23.1-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.23.1-1+deb8u5", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"quagga", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-bgpd", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-core", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-doc", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-isisd", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-ospf6d", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-ospfd", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-pimd", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-ripd", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quagga-ripngd", ver:"1.1.1-3+deb9u2", rls:"DEB9"))) {
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
