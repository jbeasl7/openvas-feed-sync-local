# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703346");
  script_cve_id("CVE-2015-6658", "CVE-2015-6659", "CVE-2015-6660", "CVE-2015-6661", "CVE-2015-6665");
  script_tag(name:"creation_date", value:"2015-08-30 22:00:00 +0000 (Sun, 30 Aug 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3346-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3346-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3346-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3346");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-3346-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Drupal, a content management framework:

CVE-2015-6658

The form autocomplete functionality did not properly sanitize the requested URL, allowing remote attackers to perform a cross-site scripting attack.

CVE-2015-6659

The SQL comment filtering system could allow a user with elevated permissions to inject malicious code in SQL comments.

CVE-2015-6660

The form API did not perform form token validation early enough, allowing the file upload callbacks to be run with untrusted input. This could allow remote attackers to upload files to the site under another user's account.

CVE-2015-6661

Users without the access content permission could see the titles of nodes that they do not have access to, if the nodes were added to a menu on the site that the users have access to.

CVE-2015-6665

Remote attackers could perform a cross-site scripting attack by invoking Drupal.ajax() on a whitelisted HTML element.

For the oldstable distribution (wheezy), these problems have been fixed in version 7.14-2+deb7u11.

For the stable distribution (jessie), these problems have been fixed in version 7.32-1+deb8u5.

For the testing distribution (stretch), these problems have been fixed in version 7.39-1.

For the unstable distribution (sid), these problems have been fixed in version 7.39-1.

We recommend that you upgrade your drupal7 packages.");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u11", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.32-1+deb8u5", rls:"DEB8"))) {
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
