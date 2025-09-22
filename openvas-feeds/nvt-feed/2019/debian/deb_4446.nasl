# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704446");
  script_cve_id("CVE-2019-12046");
  script_tag(name:"creation_date", value:"2019-05-16 02:00:07 +0000 (Thu, 16 May 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-24 11:38:01 +0000 (Fri, 24 May 2019)");

  script_name("Debian: Security Advisory (DSA-4446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4446-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4446-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4446");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/lemonldap-ng");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lemonldap-ng' package(s) announced via the DSA-4446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Lemonldap::NG web SSO system performed insufficient validation of session tokens if the tokenUseGlobalStorage option is enabled, which could grant users with access to the main session database access to an anonymous session.

For the stable distribution (stretch), this problem has been fixed in version 1.9.7-3+deb9u1.

We recommend that you upgrade your lemonldap-ng packages.

For the detailed security status of lemonldap-ng please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'lemonldap-ng' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-doc", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-fastcgi-server", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-fr-doc", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-handler", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-common-perl", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-conf-perl", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-handler-perl", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-manager-perl", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-portal-perl", ver:"1.9.7-3+deb9u1", rls:"DEB9"))) {
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
