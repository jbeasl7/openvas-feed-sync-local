# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842720");
  script_cve_id("CVE-2014-9767", "CVE-2015-8835", "CVE-2015-8838", "CVE-2016-1903", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-3185");
  script_tag(name:"creation_date", value:"2016-05-06 09:59:08 +0000 (Fri, 06 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-16 22:38:24 +0000 (Mon, 16 May 2016)");

  script_name("Ubuntu: Security Advisory (USN-2952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2952-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2952-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-2952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the PHP Zip extension incorrectly handled
directories when processing certain zip files. A remote attacker could
possibly use this issue to create arbitrary directories. (CVE-2014-9767)

It was discovered that the PHP Soap client incorrectly validated data
types. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-8835, CVE-2016-3185)

It was discovered that the PHP MySQL native driver incorrectly handled TLS
connections to MySQL databases. A machine-in-the-middle attacker could possibly
use this issue to downgrade and snoop on TLS connections. This
vulnerability is known as BACKRONYM. (CVE-2015-8838)

It was discovered that PHP incorrectly handled the imagerotate function. A
remote attacker could use this issue to cause PHP to crash, resulting in a
denial of service, or possibly obtain sensitive information. This issue
only applied to Ubuntu 14.04 LTS and Ubuntu 15.10. (CVE-2016-1903)

Hans Jerry Illikainen discovered that the PHP phar extension incorrectly
handled certain tar archives. A remote attacker could use this issue to
cause PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-2554)

It was discovered that the PHP WDDX extension incorrectly handled certain
malformed XML data. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2016-3141)

It was discovered that the PHP phar extension incorrectly handled certain
zip files. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly obtain sensitive information.
(CVE-2016-3142)

It was discovered that the PHP libxml_disable_entity_loader() setting was
shared between threads. When running under PHP-FPM, this could result in
XML external entity injection and entity expansion issues. This issue only
applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (No CVE number)

It was discovered that the PHP openssl_random_pseudo_bytes() function did
not return cryptographically strong pseudo-random bytes. (No CVE number)

It was discovered that the PHP Fileinfo component incorrectly handled
certain magic files. An attacker could use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE number pending)

It was discovered that the PHP php_snmp_error() function incorrectly
handled string formatting. A remote attacker could use this issue to cause
PHP to crash, resulting in a denial of service, or possibly execute
arbitrary code. This issue only applied to Ubuntu 14.04 LTS and Ubuntu
15.10. (CVE number pending)

It was discovered that the PHP rawurlencode() function incorrectly handled
large strings. A remote attacker could use this issue to cause PHP to
crash, resulting in a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.3.10-1ubuntu3.22", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.5.9+dfsg-1ubuntu4.16", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-fpm", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mysqlnd", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.6.11+dfsg-1ubuntu3.2", rls:"UBUNTU15.10"))) {
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
