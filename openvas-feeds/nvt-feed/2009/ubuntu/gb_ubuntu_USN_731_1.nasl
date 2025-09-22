# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63562");
  script_cve_id("CVE-2007-6203", "CVE-2007-6420", "CVE-2008-1678", "CVE-2008-2168", "CVE-2008-2364", "CVE-2008-2939");
  script_tag(name:"creation_date", value:"2009-03-13 18:24:56 +0000 (Fri, 13 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-731-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-731-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-731-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-731-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Apache did not sanitize the method specifier header from
an HTTP request when it is returned in an error message, which could result in
browsers becoming vulnerable to cross-site scripting attacks when processing the
output. With cross-site scripting vulnerabilities, if a user were tricked into
viewing server output during a crafted server request, a remote attacker could
exploit this to modify the contents, or steal confidential data (such as
passwords), within the same domain. This issue only affected Ubuntu 6.06 LTS and
7.10. (CVE-2007-6203)

It was discovered that Apache was vulnerable to a cross-site request forgery
(CSRF) in the mod_proxy_balancer balancer manager. If an Apache administrator
were tricked into clicking a link on a specially crafted web page, an attacker
could trigger commands that could modify the balancer manager configuration.
This issue only affected Ubuntu 7.10 and 8.04 LTS. (CVE-2007-6420)

It was discovered that Apache had a memory leak when using mod_ssl with
compression. A remote attacker could exploit this to exhaust server memory,
leading to a denial of service. This issue only affected Ubuntu 7.10.
(CVE-2008-1678)

It was discovered that in certain conditions, Apache did not specify a default
character set when returning certain error messages containing UTF-7 encoded
data, which could result in browsers becoming vulnerable to cross-site scripting
attacks when processing the output. This issue only affected Ubuntu 6.06 LTS and
7.10. (CVE-2008-2168)

It was discovered that when configured as a proxy server, Apache did not limit
the number of forwarded interim responses. A malicious remote server could send
a large number of interim responses and cause a denial of service via memory
exhaustion. (CVE-2008-2364)

It was discovered that mod_proxy_ftp did not sanitize wildcard pathnames when
they are returned in directory listings, which could result in browsers becoming
vulnerable to cross-site scripting attacks when processing the output.
(CVE-2008-2939)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu2.4", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.55-4ubuntu2.4", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.55-4ubuntu2.4", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.55-4ubuntu2.4", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.4-3ubuntu0.2", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.4-3ubuntu0.2", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.4-3ubuntu0.2", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.4-3ubuntu0.2", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.4-3ubuntu0.2", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.8-1ubuntu0.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.2.8-1ubuntu0.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.8-1ubuntu0.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.8-1ubuntu0.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.5", rls:"UBUNTU8.04 LTS"))) {
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
