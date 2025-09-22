# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703588");
  script_cve_id("CVE-2016-1902", "CVE-2016-4423");
  script_tag(name:"creation_date", value:"2016-05-28 22:00:00 +0000 (Sat, 28 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-02 21:11:04 +0000 (Thu, 02 Jun 2016)");

  script_name("Debian: Security Advisory (DSA-3588-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3588-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3588-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3588");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DSA-3588-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Symfony, a PHP framework.

CVE-2016-1902

Lander Brandt discovered that the class SecureRandom might generate weak random numbers for cryptographic use under certain settings. If the functions random_bytes() or openssl_random_pseudo_bytes() are not available, the output of SecureRandom should not be consider secure.

CVE-2016-4423

Marek Alaksa from Citadelo discovered that it is possible to fill up the session storage space by submitting inexistent large usernames.

For the stable distribution (jessie), these problems have been fixed in version 2.3.21+dfsg-4+deb8u3.

For the testing distribution (stretch), these problems have been fixed in version 2.8.6+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 2.8.6+dfsg-1.

We recommend that you upgrade your symfony packages.");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-classloader", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-eventdispatcher", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-locale", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-propel1-bridge", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-swiftmailer-bridge", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"2.3.21+dfsg-4+deb8u3", rls:"DEB8"))) {
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
