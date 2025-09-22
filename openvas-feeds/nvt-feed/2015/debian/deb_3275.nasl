# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703275");
  script_cve_id("CVE-2015-0850");
  script_tag(name:"creation_date", value:"2015-05-29 22:00:00 +0000 (Fri, 29 May 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3275-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3275-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3275-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3275");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fusionforge' package(s) announced via the DSA-3275-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ansgar Burchardt discovered that the Git plugin for FusionForge, a web-based project-management and collaboration software, does not sufficiently validate user provided input as parameter to the method to create secondary Git repositories. A remote attacker can use this flaw to execute arbitrary code as root via a specially crafted URL.

For the stable distribution (jessie), this problem has been fixed in version 5.3.2+20141104-3+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your fusionforge packages.");

  script_tag(name:"affected", value:"'fusionforge' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-full", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-minimal", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-admssw", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-authcas", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-authhttpd", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-authldap", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-blocks", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-compactpreview", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-contribtracker", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-doaprdf", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-extsubproj", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-foafprofiles", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-globalsearch", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-gravatar", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-headermenu", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-hudson", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-mediawiki", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-message", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-moinmoin", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-projectlabels", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmarch", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmbzr", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmcvs", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmdarcs", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmgit", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmhg", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmhook", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-scmsvn", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-plugin-sysauthldap", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusionforge-standard", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-common", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-db-postgresql", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-db-remote", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-dns-bind9", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-ftp-proftpd", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-lists-mailman", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-exim4", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-mta-postfix", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-shell-postgresql", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-web-apache2", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gforge-web-apache2-vhosts", ver:"5.3.2+20141104-3+deb8u1", rls:"DEB8"))) {
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
