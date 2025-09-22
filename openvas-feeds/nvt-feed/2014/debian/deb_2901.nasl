# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702901");
  script_cve_id("CVE-2014-0165", "CVE-2014-0166");
  script_tag(name:"creation_date", value:"2014-04-11 22:00:00 +0000 (Fri, 11 Apr 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2901-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2901-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2901-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2901");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-2901-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Wordpress, a web blogging tool. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-0165

A user with a contributor role, using a specially crafted request, can publish posts, which is reserved for users of the next-higher role.

CVE-2014-0166

Jon Cave of the WordPress security team discovered that the wp_validate_auth_cookie function in wp-includes/pluggable.php does not properly determine the validity of authentication cookies, allowing a remote attacker to obtain access via a forged cookie.

For the oldstable distribution (squeeze), these problems have been fixed in version 3.6.1+dfsg-1~deb6u2.

For the stable distribution (wheezy), these problems have been fixed in version 3.6.1+dfsg-1~deb7u2.

For the testing distribution (jessie), these problems have been fixed in version 3.8.2+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 3.8.2+dfsg-1.

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb6u2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb6u2", rls:"DEB6"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"3.6.1+dfsg-1~deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"3.6.1+dfsg-1~deb7u2", rls:"DEB7"))) {
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
