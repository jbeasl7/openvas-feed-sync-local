# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702643");
  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2274", "CVE-2013-2275");
  script_tag(name:"creation_date", value:"2013-03-11 23:00:00 +0000 (Mon, 11 Mar 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2643-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2643-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2643-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2643");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'puppet' package(s) announced via the DSA-2643-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Puppet, a centralized configuration management system.

CVE-2013-1640

An authenticated malicious client may request its catalog from the puppet master, and cause the puppet master to execute arbitrary code. The puppet master must be made to invoke the template or inline_template functions during catalog compilation.

CVE-2013-1652

An authenticated malicious client may retrieve catalogs from the puppet master that it is not authorized to access. Given a valid certificate and private key, it is possible to construct an HTTP GET request that will return a catalog for an arbitrary client.

CVE-2013-1653

An authenticated malicious client may execute arbitrary code on Puppet agents that accept kick connections. Puppet agents are not vulnerable in their default configuration. However, if the Puppet agent is configured to listen for incoming connections, e.g. listen = true, and the agent's auth.conf allows access to the run REST endpoint, then an authenticated client can construct an HTTP PUT request to execute arbitrary code on the agent. This issue is made worse by the fact that puppet agents typically run as root.

CVE-2013-1654

A bug in Puppet allows SSL connections to be downgraded to SSLv2, which is known to contain design flaw weaknesses. This affects SSL connections between puppet agents and master, as well as connections that puppet agents make to third party servers that accept SSLv2 connections. Note that SSLv2 is disabled since OpenSSL 1.0.

CVE-2013-1655

An unauthenticated malicious client may send requests to the puppet master, and have the master load code in an unsafe manner. It only affects users whose puppet masters are running ruby 1.9.3 and above.

CVE-2013-2274

An authenticated malicious client may execute arbitrary code on the puppet master in its default configuration. Given a valid certificate and private key, a client can construct an HTTP PUT request that is authorized to save the client's own report, but the request will actually cause the puppet master to execute arbitrary code.

CVE-2013-2275

The default auth.conf allows an authenticated node to submit a report for any other node, which is a problem for compliance. It has been made more restrictive by default so that a node is only allowed to save its own report.

For the stable distribution (squeeze), these problems have been fixed in version 2.6.2-5+squeeze7.

For the testing distribution (wheezy), these problems have been fixed in version 2.7.18-3.

For the unstable distribution (sid), these problems have been fixed in version 2.7.18-3.

We recommend that you upgrade your puppet packages.");

  script_tag(name:"affected", value:"'puppet' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"puppet", ver:"2.6.2-5+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.2-5+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppet-el", ver:"2.6.2-5+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.6.2-5+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"puppetmaster", ver:"2.6.2-5+squeeze7", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-puppet", ver:"2.6.2-5+squeeze7", rls:"DEB6"))) {
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
