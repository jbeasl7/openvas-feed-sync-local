# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66457");
  script_cve_id("CVE-2009-3304");
  script_tag(name:"creation_date", value:"2009-12-09 23:23:54 +0000 (Wed, 09 Dec 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1945-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1945-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1945-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1945");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gforge' package(s) announced via the DSA-1945-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sylvain Beucler discovered that gforge, a collaborative development tool, is prone to a symlink attack, which allows local users to perform a denial of service attack by overwriting arbitrary files.

The oldstable distribution (etch), this problem has been fixed in version 4.5.14-22etch13.

For the stable distribution (lenny), this problem has been fixed in version 4.7~rc2-7lenny3.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 4.8.2-1.

We recommend that you upgrade your gforge packages.");

  script_tag(name:"affected", value:"'gforge' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"gforge", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-common", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-db-postgresql", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-dns-bind9", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-ftp-proftpd", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-ldap-openldap", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-lists-mailman", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-courier", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-exim", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-exim4", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-postfix", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-shell-ldap", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-shell-postgresql", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-web-apache", ver:"4.5.14-22etch13", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"gforge", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-common", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-db-postgresql", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-dns-bind9", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-ftp-proftpd", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-lists-mailman", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-courier", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-exim4", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-postfix", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-plugin-mediawiki", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-plugin-scmcvs", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-plugin-scmsvn", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-shell-postgresql", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-web-apache", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-web-apache2", ver:"4.7~rc2-7lenny3", rls:"DEB5"))) {
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
