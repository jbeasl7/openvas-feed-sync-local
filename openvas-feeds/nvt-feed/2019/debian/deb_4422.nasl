# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704422");
  script_cve_id("CVE-2018-17189", "CVE-2018-17199", "CVE-2019-0196", "CVE-2019-0211", "CVE-2019-0217", "CVE-2019-0220");
  script_tag(name:"creation_date", value:"2019-04-06 02:00:17 +0000 (Sat, 06 Apr 2019)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 14:58:33 +0000 (Thu, 25 Jul 2024)");

  script_name("Debian: Security Advisory (DSA-4422-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4422-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4422-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4422");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apache2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache2' package(s) announced via the DSA-4422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTP server.

CVE-2018-17189

Gal Goldshtein of F5 Networks discovered a denial of service vulnerability in mod_http2. By sending malformed requests, the http/2 stream for that request unnecessarily occupied a server thread cleaning up incoming data, resulting in denial of service.

CVE-2018-17199

Diego Angulo from ImExHS discovered that mod_session_cookie does not respect expiry time.

CVE-2019-0196

Craig Young discovered that the http/2 request handling in mod_http2 could be made to access freed memory in string comparison when determining the method of a request and thus process the request incorrectly.

CVE-2019-0211

Charles Fol discovered a privilege escalation from the less-privileged child process to the parent process running as root.

CVE-2019-0217

A race condition in mod_auth_digest when running in a threaded server could allow a user with valid credentials to authenticate using another username, bypassing configured access control restrictions. The issue was discovered by Simon Kappel.

CVE-2019-0220

Bernhard Lorenz of Alpha Strike Labs GmbH reported that URL normalizations were inconsistently handled. When the path component of a request URL contains multiple consecutive slashes ('/'), directives such as LocationMatch and RewriteRule must account for duplicates in regular expressions while other aspects of the servers processing will implicitly collapse them.

For the stable distribution (stretch), these problems have been fixed in version 2.4.25-3+deb9u7.

This update also contains bug fixes that were scheduled for inclusion in the next stable point release. This includes a fix for a regression caused by a security fix in version 2.4.25-3+deb9u6.

We recommend that you upgrade your apache2 packages.

For the detailed security status of apache2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-ssl-dev", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.25-3+deb9u7", rls:"DEB9"))) {
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
