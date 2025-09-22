# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891707");
  script_cve_id("CVE-2017-16652", "CVE-2017-16654", "CVE-2018-11385", "CVE-2018-11408", "CVE-2018-14773", "CVE-2018-19789", "CVE-2018-19790");
  script_tag(name:"creation_date", value:"2019-03-10 23:00:00 +0000 (Sun, 10 Mar 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 12:31:36 +0000 (Fri, 03 Aug 2018)");

  script_name("Debian: Security Advisory (DLA-1707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1707-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1707-1");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2017-16652-open-redirect-vulnerability-on-security-handlers");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2017-16654-intl-bundle-readers-breaking-out-of-paths");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-11385-session-fixation-issue-for-guard-authentication");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-11408-open-redirect-vulnerability-on-security-handlers");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-19789-disclosure-of-uploaded-files-full-path");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2018-19790-open-redirect-vulnerability-when-using-security-http");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DLA-1707-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in symfony, a PHP web application framework. Numerous symfony components are affected: Security, bundle readers, session handling, SecurityBundle, HttpFoundation, Form, and SecurityHttp.

The corresponding upstream advisories contain further details:

[CVE-2017-16652] [link moved to references]

[CVE-2017-16654] [link moved to references]

[CVE-2018-11385] [link moved to references]

[CVE-2018-11408] [link moved to references]

[CVE-2018-14773] [link moved to references]

[CVE-2018-19789] [link moved to references]

[CVE-2018-19790] [link moved to references]

For Debian 8 Jessie, these problems have been fixed in version 2.3.21+dfsg-4+deb8u4.

We recommend that you upgrade your symfony packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

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

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-browser-kit", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-class-loader", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-classloader", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-config", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-console", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-css-selector", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-debug", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dependency-injection", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-doctrine-bridge", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-dom-crawler", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-event-dispatcher", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-eventdispatcher", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-filesystem", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-finder", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-form", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-framework-bundle", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-foundation", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-http-kernel", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-intl", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-locale", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-monolog-bridge", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-options-resolver", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-process", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-propel1-bridge", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-property-access", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-proxy-manager-bridge", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-routing", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-security-bundle", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-serializer", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-stopwatch", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-swiftmailer-bridge", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-templating", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-translation", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bridge", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-twig-bundle", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-validator", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-web-profiler-bundle", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-symfony-yaml", ver:"2.3.21+dfsg-4+deb8u4", rls:"DEB8"))) {
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
