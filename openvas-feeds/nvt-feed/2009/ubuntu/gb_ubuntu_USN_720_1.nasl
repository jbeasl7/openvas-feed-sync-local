# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64167");
  script_cve_id("CVE-2007-3996", "CVE-2007-5900", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658");
  script_tag(name:"creation_date", value:"2009-06-05 16:04:08 +0000 (Fri, 05 Jun 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-720-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-720-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-720-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-720-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP did not properly enforce php_admin_value and
php_admin_flag restrictions in the Apache configuration file. A local attacker
could create a specially crafted PHP script that would bypass intended security
restrictions. This issue only applied to Ubuntu 6.06 LTS, 7.10, and 8.04 LTS.
(CVE-2007-5900)

It was discovered that PHP did not correctly handle certain malformed font
files. If a PHP application were tricked into processing a specially crafted
font file, an attacker may be able to cause a denial of service and possibly
execute arbitrary code with application privileges. (CVE-2008-3658)

It was discovered that PHP did not properly check the delimiter argument to the
explode function. If a script passed untrusted input to the explode function, an
attacker could cause a denial of service and possibly execute arbitrary code
with application privileges. (CVE-2008-3659)

It was discovered that PHP, when used as FastCGI module, did not properly
sanitize requests. By performing a request with multiple dots preceding the
extension, an attacker could cause a denial of service. (CVE-2008-3660)

It was discovered that PHP did not properly handle Unicode conversion in the
mbstring extension. If a PHP application were tricked into processing a
specially crafted string containing an HTML entity, an attacker could execute
arbitrary code with application privileges. (CVE-2008-5557)

It was discovered that PHP did not properly initialize the page_uid and page_gid
global variables for use by the SAPI php_getuid function. An attacker could
exploit this issue to bypass safe_mode restrictions. (CVE-2008-5624)

It was discovered that PHP did not properly enforce error_log safe_mode
restrictions when set by php_admin_flag in the Apache configuration file. A
local attacker could create a specially crafted PHP script that would overwrite
arbitrary files. (CVE-2008-5625)

It was discovered that PHP contained a flaw in the ZipArchive::extractTo
function. If a PHP application were tricked into processing a specially crafted
zip file that had filenames containing '..', an attacker could write arbitrary
files within the filesystem. This issue only applied to Ubuntu 7.10, 8.04 LTS,
and 8.10. (CVE-2008-5658)

USN-557-1 fixed a vulnerability in the GD library. When using the GD library,
PHP did not properly handle the return codes that were added in the security
update. An attacker could exploit this issue with a specially crafted image file
and cause PHP to crash, leading to a denial of service. This issue only applied
to Ubuntu 6.06 LTS, and 7.10. (CVE-2007-3996)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.1.2-1ubuntu3.13", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.1.2-1ubuntu3.13", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.1.2-1ubuntu3.13", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.1.2-1ubuntu3.13", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.3-1ubuntu6.5", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.3-1ubuntu6.5", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.3-1ubuntu6.5", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.3-1ubuntu6.5", rls:"UBUNTU7.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.4-2ubuntu5.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.4-2ubuntu5.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.4-2ubuntu5.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.4-2ubuntu5.5", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.6-2ubuntu4.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.2.6-2ubuntu4.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.6-2ubuntu4.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.6-2ubuntu4.1", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.6-2ubuntu4.1", rls:"UBUNTU8.10"))) {
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
