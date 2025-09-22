# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840636");
  script_cve_id("CVE-2006-7243", "CVE-2010-4697", "CVE-2010-4698", "CVE-2011-0420", "CVE-2011-0421", "CVE-2011-0441", "CVE-2011-0708", "CVE-2011-1072", "CVE-2011-1144");
  script_tag(name:"creation_date", value:"2011-05-10 12:04:15 +0000 (Tue, 10 May 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1126-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|6\.06\ LTS|8\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1126-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1126-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/774452");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/776642");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-1126-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN 1126-1 fixed several vulnerabilities in PHP. The fix for
CVE-2010-4697 introduced an incorrect reference counting regression
in the Zend engine that caused the PHP interpreter to segfault. This
regression affects Ubuntu 6.06 LTS and Ubuntu 8.04 LTS.

The fixes for CVE-2011-1072 and CVE-2011-1144 introduced a regression
in the PEAR installer that prevented it from creating its cache
directory and reporting errors correctly.

We apologize for the inconvenience.

Original advisory details:

 Stephane Chazelas discovered that the /etc/cron.d/php5 cron job for
 PHP 5.3.5 allows local users to delete arbitrary files via a symlink
 attack on a directory under /var/lib/php5/. (CVE-2011-0441)

 Raphael Geisert and Dan Rosenberg discovered that the PEAR installer
 allows local users to overwrite arbitrary files via a symlink attack on
 the package.xml file, related to the (1) download_dir, (2) cache_dir,
 (3) tmp_dir, and (4) pear-build-download directories. (CVE-2011-1072,
 CVE-2011-1144)

 Ben Schmidt discovered that a use-after-free vulnerability in the PHP
 Zend engine could allow an attacker to cause a denial of service (heap
 memory corruption) or possibly execute arbitrary code. (CVE-2010-4697)

 Martin Barbella discovered a buffer overflow in the PHP GD extension
 that allows an attacker to cause a denial of service (application crash)
 via a large number of anti- aliasing steps in an argument to the
 imagepstext function. (CVE-2010-4698)

 It was discovered that PHP accepts the \0 character in a pathname,
 which might allow an attacker to bypass intended access restrictions
 by placing a safe file extension after this character. This issue
 is addressed in Ubuntu 10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04.
 (CVE-2006-7243)

 Maksymilian Arciemowicz discovered that the grapheme_extract function
 in the PHP Internationalization extension (Intl) for ICU allow
 an attacker to cause a denial of service (crash) via an invalid
 size argument, which triggers a NULL pointer dereference. This
 issue affected Ubuntu 10.04 LTS, Ubuntu 10.10, and Ubuntu
 11.04. (CVE-2011-0420)

 Maksymilian Arciemowicz discovered that the _zip_name_locate
 function in the PHP Zip extension does not properly handle a
 ZIPARCHIVE::FL_UNCHANGED argument, which might allow an attacker to
 cause a denial of service (NULL pointer dereference) via an empty
 ZIP archive. This issue affected Ubuntu 8.04 LTS, Ubuntu 9.10, Ubuntu
 10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04. (CVE-2011-0421)

 Luca Carettoni discovered that the PHP Exif extension performs an
 incorrect cast on 64bit platforms, which allows a remote attacker
 to cause a denial of service (application crash) via an image with
 a crafted Image File Directory (IFD). (CVE-2011-0708)

 Jose Carlos Norte discovered that an integer overflow in the PHP
 shmop extension could allow an attacker to cause a denial of service
 (crash) and possibly read ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.2-1ubuntu4.9", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.3.2-1ubuntu4.9", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.2-1ubuntu4.9", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.2-1ubuntu4.9", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.2-1ubuntu4.9", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.3.2-1ubuntu4.9", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.3-1ubuntu9.5", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.3.3-1ubuntu9.5", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.3-1ubuntu9.5", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.3-1ubuntu9.5", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.3-1ubuntu9.5", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.3.3-1ubuntu9.5", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.3.5-1ubuntu7.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.3.5-1ubuntu7.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.3.5-1ubuntu7.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.3.5-1ubuntu7.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.3.5-1ubuntu7.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.3.5-1ubuntu7.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.1.2-1ubuntu3.24", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.1.2-1ubuntu3.24", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.1.2-1ubuntu3.24", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.1.2-1ubuntu3.24", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.1.2-1ubuntu3.24", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.1.2-1ubuntu3.24", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.4-2ubuntu5.17", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.2.4-2ubuntu5.17", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.2.4-2ubuntu5.17", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.4-2ubuntu5.17", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.4-2ubuntu5.17", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.2.4-2ubuntu5.17", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.10.dfsg.1-2ubuntu6.10", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.2.10.dfsg.1-2ubuntu6.10", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.2.10.dfsg.1-2ubuntu6.10", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.10.dfsg.1-2ubuntu6.10", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.10.dfsg.1-2ubuntu6.10", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.2.10.dfsg.1-2ubuntu6.10", rls:"UBUNTU9.10"))) {
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
