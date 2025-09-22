# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702757");
  script_cve_id("CVE-2013-4338", "CVE-2013-4339", "CVE-2013-4340", "CVE-2013-5738", "CVE-2013-5739");
  script_tag(name:"creation_date", value:"2013-09-13 22:00:00 +0000 (Fri, 13 Sep 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2757-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2757-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2757-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2757");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-2757-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were identified in Wordpress, a web blogging tool. As the CVEs were allocated from releases announcements and specific fixes are usually not identified, it has been decided to upgrade the Wordpress package to the latest upstream version instead of backporting the patches.

This means extra care should be taken when upgrading, especially when using third-party plugins or themes, since compatibility may have been impacted along the way. We recommend that users check their install before doing the upgrade.

CVE-2013-4338

Unsafe PHP unserialization in wp-includes/functions.php could cause arbitrary code execution.

CVE-2013-4339

Insufficient input validation could result in redirecting or leading a user to another website.

CVE-2013-4340

Privilege escalation allowing an user with an author role to create an entry appearing as written by another user.

CVE-2013-5738

Insufficient capabilities were required for uploading .html/.html files, making it easier for authenticated users to conduct cross-site scripting attacks (XSS) using crafted html file uploads.

CVE-2013-5739

Default Wordpress configuration allowed file upload for .swf/.exe files, making it easier for authenticated users to conduct cross-site scripting attacks (XSS).

For the oldstable distribution (squeeze), these problems have been fixed in version 3.6.1+dfsg-1~deb6u1.

For the stable distribution (wheezy), these problems have been fixed in version 3.6.1+dfsg-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in version 3.6.1+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 3.6.1+dfsg-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u1", rls:"DEB7"))) {
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
