# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842844");
  script_cve_id("CVE-2015-4116", "CVE-2015-8873", "CVE-2015-8876", "CVE-2015-8935", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096", "CVE-2016-5114", "CVE-2016-5385", "CVE-2016-5399", "CVE-2016-5768", "CVE-2016-5769", "CVE-2016-5771", "CVE-2016-5772", "CVE-2016-5773", "CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6294", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297");
  script_tag(name:"creation_date", value:"2016-08-08 09:41:52 +0000 (Mon, 08 Aug 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-27 18:45:01 +0000 (Wed, 27 Jul 2016)");

  script_name("Ubuntu: Security Advisory (USN-3045-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3045-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3045-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5, php7.0' package(s) announced via the USN-3045-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP incorrectly handled certain SplMinHeap::compare
operations. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-4116)

It was discovered that PHP incorrectly handled recursive method calls. A
remote attacker could use this issue to cause PHP to crash, resulting in a
denial of service. This issue only affected Ubuntu 12.04 LTS and Ubuntu
14.04 LTS. (CVE-2015-8873)

It was discovered that PHP incorrectly validated certain Exception objects
when unserializing data. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (CVE-2015-8876)

It was discovered that PHP header() function performed insufficient
filtering for Internet Explorer. A remote attacker could possibly use this
issue to perform a XSS attack. This issue only affected Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2015-8935)

It was discovered that PHP incorrectly handled certain locale operations.
An attacker could use this issue to cause PHP to crash, resulting in a
denial of service. This issue only affected Ubuntu 12.04 LTS and Ubuntu
14.04 LTS. (CVE-2016-5093)

It was discovered that the PHP php_html_entities() function incorrectly
handled certain string lengths. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (CVE-2016-5094, CVE-2016-5095)

It was discovered that the PHP fread() function incorrectly handled certain
lengths. An attacker could use this issue to cause PHP to crash, resulting
in a denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-5096)

It was discovered that the PHP FastCGI Process Manager (FPM) SAPI
incorrectly handled memory in the access logging feature. An attacker could
use this issue to cause PHP to crash, resulting in a denial of service, or
possibly expose sensitive information. This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-5114)

It was discovered that PHP would not protect applications from contents of
the HTTP_PROXY environment variable when based on the contents of the Proxy
header from HTTP requests. A remote attacker could possibly use this issue
in combination with scripts that honour the HTTP_PROXY variable to redirect
outgoing HTTP requests. (CVE-2016-5385)

Hans Jerry Illikainen discovered that the PHP bzread() function incorrectly
performed error handling. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-5399)

It was ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php5, php7.0' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.24", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.24", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.24", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.24", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.19", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.19", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.19", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.19", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.0", ver:"7.0.8-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cgi", ver:"7.0.8-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cli", ver:"7.0.8-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-fpm", ver:"7.0.8-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
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
