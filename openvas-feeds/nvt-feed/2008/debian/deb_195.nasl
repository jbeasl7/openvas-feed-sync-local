# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53738");
  script_cve_id("CVE-2001-0131", "CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843", "CVE-2002-1233");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-195)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-195");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-195");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-195");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache-perl' package(s) announced via the DSA-195 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"According to David Wagner, iDEFENSE and the Apache HTTP Server Project, several vulnerabilities have been found in the Apache server package, a commonly used webserver. Most of the code is shared between the Apache and Apache-Perl packages, so vulnerabilities are shared as well.

These vulnerabilities could allow an attacker to enact a denial of service against a server or execute a cross site scripting attack, or steal cookies from other web site users. The Common Vulnerabilities and Exposures (CVE) project identified the following vulnerabilities:

CAN-2002-0839: A vulnerability exists on platforms using System V shared memory based scoreboards. This vulnerability allows an attacker to execute code under the Apache UID to exploit the Apache shared memory scoreboard format and send a signal to any process as root or cause a local denial of service attack.

CAN-2002-0840: Apache is susceptible to a cross site scripting vulnerability in the default 404 page of any web server hosted on a domain that allows wildcard DNS lookups.

CAN-2002-0843: There were some possible overflows in the utility ApacheBench (ab) which could be exploited by a malicious server. No such binary programs are distributed by the Apache-Perl package, though.

CAN-2002-1233: A race condition in the htpasswd and htdigest program enables a malicious local user to read or even modify the contents of a password file or easily create and overwrite files as the user running the htpasswd (or htdigest respectively) program. No such binary programs are distributed by the Apache-Perl package, though.

CAN-2001-0131: htpasswd and htdigest in Apache 2.0a9, 1.3.14, and others allows local users to overwrite arbitrary files via a symlink attack. No such binary programs are distributed by the Apache-Perl package, though.

NO-CAN: Several buffer overflows have been found in the ApacheBench (ab) utility that could be exploited by a remote server returning very long strings. No such binary programs are distributed by the Apache-Perl package, though.

These problems have been fixed in version 1.3.26-1-1.26-0woody2 for the current stable distribution (woody), in 1.3.9-14.1-1.21.20000309-1.1 for the old stable distribution (potato) and in version 1.3.26-1.1-1.27-3-1 for the unstable distribution (sid).

We recommend that you upgrade your Apache-Perl package immediately.");

  script_tag(name:"affected", value:"'apache-perl' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache-perl", ver:"1.3.26-1-1.26-0woody2", rls:"DEB3.0"))) {
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
