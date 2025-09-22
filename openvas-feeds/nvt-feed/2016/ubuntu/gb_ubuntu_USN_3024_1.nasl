# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842823");
  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763", "CVE-2016-3092");
  script_tag(name:"creation_date", value:"2016-07-06 03:25:52 +0000 (Wed, 06 Jul 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-07 17:19:27 +0000 (Thu, 07 Jul 2016)");

  script_name("Ubuntu: Security Advisory (USN-3024-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3024-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3024-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6, tomcat7' package(s) announced via the USN-3024-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly handled pathnames used by web
applications in a getResource, getResourceAsStream, or getResourcePaths
call. A remote attacker could use this issue to possibly list a parent
directory . This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 15.10. (CVE-2015-5174)

It was discovered that the Tomcat mapper component incorrectly handled
redirects. A remote attacker could use this issue to determine the
existence of a directory. This issue only affected Ubuntu 12.04 LTS,
Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5345)

It was discovered that Tomcat incorrectly handled different session
settings when multiple versions of the same web application was deployed. A
remote attacker could possibly use this issue to hijack web sessions. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2015-5346)

It was discovered that the Tomcat Manager and Host Manager applications
incorrectly handled new requests. A remote attacker could possibly use this
issue to bypass CSRF protection mechanisms. This issue only affected Ubuntu
14.04 LTS and Ubuntu 15.10. (CVE-2015-5351)

It was discovered that Tomcat did not place StatusManagerServlet on the
RestrictedServlets list. A remote attacker could possibly use this issue to
read arbitrary HTTP requests, including session ID values. This issue only
affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10.
(CVE-2016-0706)

It was discovered that the Tomcat session-persistence implementation
incorrectly handled session attributes. A remote attacker could possibly
use this issue to execute arbitrary code in a privileged context. This
issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 15.10.
(CVE-2016-0714)

It was discovered that the Tomcat setGlobalContext method incorrectly
checked if callers were authorized. A remote attacker could possibly use
this issue to read or write to arbitrary application data, or cause a denial
of service. This issue only affected Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 15.10. (CVE-2016-0763)

It was discovered that the Tomcat Fileupload library incorrectly handled
certain upload requests. A remote attacker could possibly use this issue to
cause a denial of service. (CVE-2016-3092)");

  script_tag(name:"affected", value:"'tomcat6, tomcat7' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.35-1ubuntu3.7", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.52-1ubuntu0.6", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.64-1ubuntu0.3", rls:"UBUNTU15.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.68-1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
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
