# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843024");
  script_cve_id("CVE-2016-0762", "CVE-2016-5018", "CVE-2016-5388", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735", "CVE-2016-8745", "CVE-2016-9774", "CVE-2016-9775");
  script_tag(name:"creation_date", value:"2017-01-24 09:19:27 +0000 (Tue, 24 Jan 2017)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 19:23:35 +0000 (Thu, 27 Jun 2024)");

  script_name("Ubuntu: Security Advisory (USN-3177-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3177-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3177-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6, tomcat7, tomcat8' package(s) announced via the USN-3177-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Tomcat realm implementations incorrectly handled
passwords when a username didn't exist. A remote attacker could possibly
use this issue to enumerate usernames. This issue only applied to Ubuntu
12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-0762)

Alvaro Munoz and Alexander Mirosh discovered that Tomcat incorrectly
limited use of a certain utility method. A malicious application could
possibly use this to bypass Security Manager restrictions. This issue only
applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-5018)

It was discovered that Tomcat did not protect applications from untrusted
data in the HTTP_PROXY environment variable. A remote attacker could
possibly use this issue to redirect outbound traffic to an arbitrary proxy
server. This issue only applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-5388)

It was discovered that Tomcat incorrectly controlled reading system
properties. A malicious application could possibly use this to bypass
Security Manager restrictions. This issue only applied to Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6794)

It was discovered that Tomcat incorrectly controlled certain configuration
parameters. A malicious application could possibly use this to bypass
Security Manager restrictions. This issue only applied to Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6796)

It was discovered that Tomcat incorrectly limited access to global JNDI
resources. A malicious application could use this to access any global JNDI
resource without an explicit ResourceLink. This issue only applied to
Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6797)

Regis Leroy discovered that Tomcat incorrectly filtered certain invalid
characters from the HTTP request line. A remote attacker could possibly
use this issue to inject data into HTTP responses. (CVE-2016-6816)

Pierre Ernst discovered that the Tomcat JmxRemoteLifecycleListener did not
implement a recommended fix. A remote attacker could possibly use this
issue to execute arbitrary code. (CVE-2016-8735)

It was discovered that Tomcat incorrectly handled error handling in the
send file code. A remote attacker could possibly use this issue to access
information from other requests. (CVE-2016-8745)

Paul Szabo discovered that the Tomcat package incorrectly handled upgrades
and removals. A local attacker could possibly use this issue to obtain
root privileges. (CVE-2016-9774, CVE-2016-9775)");

  script_tag(name:"affected", value:"'tomcat6, tomcat7, tomcat8' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-1ubuntu3.9", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.35-1ubuntu3.9", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.8", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.52-1ubuntu0.8", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.32-1ubuntu1.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.32-1ubuntu1.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.37-1ubuntu0.1", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.37-1ubuntu0.1", rls:"UBUNTU16.10"))) {
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
