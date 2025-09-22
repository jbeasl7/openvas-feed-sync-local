# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840304");
  script_cve_id("CVE-2006-3918", "CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2007-6421", "CVE-2007-6422", "CVE-2008-0005");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-575-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-575-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-575-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-575-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Apache did not sanitize the Expect header from
an HTTP request when it is reflected back in an error message, which
could result in browsers becoming vulnerable to cross-site scripting
attacks when processing the output. With cross-site scripting
vulnerabilities, if a user were tricked into viewing server output
during a crafted server request, a remote attacker could exploit this
to modify the contents, or steal confidential data (such as passwords),
within the same domain. This was only vulnerable in Ubuntu 6.06.
(CVE-2006-3918)

It was discovered that when configured as a proxy server and using a
threaded MPM, Apache did not properly sanitize its input. A remote
attacker could send Apache crafted date headers and cause a denial of
service via application crash. By default, mod_proxy is disabled in
Ubuntu. (CVE-2007-3847)

It was discovered that mod_autoindex did not force a character set,
which could result in browsers becoming vulnerable to cross-site
scripting attacks when processing the output. (CVE-2007-4465)

It was discovered that mod_imap/mod_imagemap did not force a
character set, which could result in browsers becoming vulnerable
to cross-site scripting attacks when processing the output. By
default, mod_imap/mod_imagemap is disabled in Ubuntu. (CVE-2007-5000)

It was discovered that mod_status when status pages were available,
allowed for cross-site scripting attacks. By default, mod_status is
disabled in Ubuntu. (CVE-2007-6388)

It was discovered that mod_proxy_balancer did not sanitize its input,
which could result in browsers becoming vulnerable to cross-site
scripting attacks when processing the output. By default,
mod_proxy_balancer is disabled in Ubuntu. This was only vulnerable
in Ubuntu 7.04 and 7.10. (CVE-2007-6421)

It was discovered that mod_proxy_balancer could be made to
dereference a NULL pointer. A remote attacker could send a crafted
request and cause a denial of service via application crash. By
default, mod_proxy_balancer is disabled in Ubuntu. This was only
vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-6422)

It was discovered that mod_proxy_ftp did not force a character set,
which could result in browsers becoming vulnerable to cross-site
scripting attacks when processing the output. By default,
mod_proxy_ftp is disabled in Ubuntu. (CVE-2008-0005)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu2.3", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu4.2", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.3-3.2ubuntu2.1", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.4-3ubuntu0.1", rls:"UBUNTU7.10"))) {
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
