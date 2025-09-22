# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703375");
  script_cve_id("CVE-2015-5714", "CVE-2015-5715", "CVE-2015-7989");
  script_tag(name:"creation_date", value:"2015-10-18 22:00:00 +0000 (Sun, 18 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-23 14:44:22 +0000 (Mon, 23 May 2016)");

  script_name("Debian: Security Advisory (DSA-3375-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3375-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3375-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3375");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-3375-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in Wordpress, the popular blogging engine.

CVE-2015-5714

A cross-site scripting vulnerability when processing shortcode tags has been discovered.

The issue has been fixed by not allowing unclosed HTML elements in attributes.

CVE-2015-5715

A vulnerability has been discovered, allowing users without proper permissions to publish private posts and make them sticky.

The issue has been fixed in the XMLRPC code of Wordpress by not allowing private posts to be sticky.

CVE-2015-7989

A cross-site scripting vulnerability in user list tables has been discovered.

The issue has been fixed by URL-escaping email addresses in those user lists.

For the oldstable distribution (wheezy), these problems will be fixed in later update.

For the stable distribution (jessie), these problems have been fixed in version 4.1+dfsg-1+deb8u5.

For the testing distribution (stretch), these problems have been fixed in version 4.3.1+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 4.3.1+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.1+dfsg-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.1+dfsg-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.1+dfsg-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfourteen", ver:"4.1+dfsg-1+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentythirteen", ver:"4.1+dfsg-1+deb8u5", rls:"DEB8"))) {
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
