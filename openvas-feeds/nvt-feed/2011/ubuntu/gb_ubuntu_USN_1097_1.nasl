# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840622");
  script_cve_id("CVE-2010-3718", "CVE-2011-0013", "CVE-2011-0534");
  script_tag(name:"creation_date", value:"2011-04-01 13:34:04 +0000 (Fri, 01 Apr 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1097-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1097-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1097-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6' package(s) announced via the USN-1097-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Tomcat SecurityManager did not properly restrict
the working directory. An attacker could use this flaw to read or write
files outside of the intended working directory. (CVE-2010-3718)

It was discovered that Tomcat did not properly escape certain parameters in
the Manager application which could result in browsers becoming vulnerable
to cross-site scripting attacks when processing the output. With cross-site
scripting vulnerabilities, if a user were tricked into viewing server
output during a crafted server request, a remote attacker could exploit
this to modify the contents, or steal confidential data (such as
passwords), within the same domain. (CVE-2011-0013)

It was discovered that Tomcat incorrectly enforced the maxHttpHeaderSize
limit in certain configurations. A remote attacker could use this flaw to
cause Tomcat to consume all available memory, resulting in a denial of
service. (CVE-2011-0534)");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.24-2ubuntu1.7", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.24-2ubuntu1.7", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.28-2ubuntu1.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.28-2ubuntu1.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.20-2ubuntu2.4", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.20-2ubuntu2.4", rls:"UBUNTU9.10"))) {
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
