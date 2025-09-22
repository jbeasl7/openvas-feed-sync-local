# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64262");
  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
  script_tag(name:"creation_date", value:"2009-06-23 13:49:15 +0000 (Tue, 23 Jun 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2009-06-08 12:50:00 +0000 (Mon, 08 Jun 2009)");

  script_name("Ubuntu: Security Advisory (USN-788-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-788-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-788-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6' package(s) announced via the USN-788-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Iida Minehiko discovered that Tomcat did not properly normalise paths. A
remote attacker could send specially crafted requests to the server and
bypass security restrictions, gaining access to sensitive content.
(CVE-2008-5515)

Yoshihito Fukuyama discovered that Tomcat did not properly handle errors
when the Java AJP connector and mod_jk load balancing are used. A remote
attacker could send specially crafted requests containing invalid headers
to the server and cause a temporary denial of service. (CVE-2009-0033)

D. Matscheko and T. Hackner discovered that Tomcat did not properly handle
malformed URL encoding of passwords when FORM authentication is used. A
remote attacker could exploit this in order to enumerate valid usernames.
(CVE-2009-0580)

Deniz Cevik discovered that Tomcat did not properly escape certain
parameters in the example calendar application which could result in
browsers becoming vulnerable to cross-site scripting attacks when
processing the output. With cross-site scripting vulnerabilities, if a user
were tricked into viewing server output during a crafted server request, a
remote attacker could exploit this to modify the contents, or steal
confidential data (such as passwords), within the same domain.
(CVE-2009-0781)

Philippe Prados discovered that Tomcat allowed web applications to replace
the XML parser used by other web applications. Local users could exploit
this to bypass security restrictions and gain access to certain sensitive
files. (CVE-2009-0783)");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.18-0ubuntu3.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.18-0ubuntu6.1", rls:"UBUNTU9.04"))) {
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
