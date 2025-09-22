# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843539");
  script_cve_id("CVE-2017-12616", "CVE-2017-12617", "CVE-2017-15706", "CVE-2018-1304", "CVE-2018-1305", "CVE-2018-8014");
  script_tag(name:"creation_date", value:"2018-06-05 08:33:23 +0000 (Tue, 05 Jun 2018)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 17:44:20 +0000 (Wed, 20 Jun 2018)");

  script_name("Ubuntu: Security Advisory (USN-3665-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3665-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3665-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7, tomcat8' package(s) announced via the USN-3665-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly handled being configured with
HTTP PUTs enabled. A remote attacker could use this issue to upload a JSP
file to the server and execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2017-12616,
CVE-2017-12617)

It was discovered that Tomcat contained incorrect documentation regarding
description of the search algorithm used by the CGI Servlet to identify
which script to execute. This issue only affected Ubuntu 17.10.
(CVE-2017-15706)

It was discovered that Tomcat incorrectly handled en empty string URL
pattern in security constraint definitions. A remote attacker could
possibly use this issue to gain access to web application resources,
contrary to expectations. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-1304)

It was discovered that Tomcat incorrectly handled applying certain security
constraints. A remote attacker could possibly access certain resources,
contrary to expectations. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-1305)

It was discovered that the Tomcat CORS filter default settings were
insecure and would enable 'supportsCredentials' for all origins, contrary
to expectations. (CVE-2018-8014)");

  script_tag(name:"affected", value:"'tomcat7, tomcat8' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.14", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.52-1ubuntu0.14", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.32-1ubuntu1.6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.32-1ubuntu1.6", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.21-1ubuntu1.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.21-1ubuntu1.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.30-1ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.30-1ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
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
