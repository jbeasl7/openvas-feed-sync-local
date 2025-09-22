# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704193");
  script_cve_id("CVE-2018-10100", "CVE-2018-10102");
  script_tag(name:"creation_date", value:"2018-05-04 22:00:00 +0000 (Fri, 04 May 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 13:50:36 +0000 (Fri, 18 May 2018)");

  script_name("Debian: Security Advisory (DSA-4193-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4193-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4193-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4193");
  script_xref(name:"URL", value:"https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wordpress");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-4193-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in wordpress, a web blogging tool, which could allow remote attackers to compromise a site via cross-site scripting, bypass restrictions or unsafe redirects. More information can be found in the upstream advisory at [link moved to references]

For the oldstable distribution (jessie), these problems have been fixed in version 4.1+dfsg-1+deb8u17.

For the stable distribution (stretch), these problems have been fixed in version 4.7.5+dfsg-2+deb9u3.

We recommend that you upgrade your wordpress packages.

For the detailed security status of wordpress please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.1+dfsg-1+deb8u17", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.1+dfsg-1+deb8u17", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.1+dfsg-1+deb8u17", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfourteen", ver:"4.1+dfsg-1+deb8u17", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentythirteen", ver:"4.1+dfsg-1+deb8u17", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"4.7.5+dfsg-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-l10n", ver:"4.7.5+dfsg-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyfifteen", ver:"4.7.5+dfsg-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentyseventeen", ver:"4.7.5+dfsg-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wordpress-theme-twentysixteen", ver:"4.7.5+dfsg-2+deb9u3", rls:"DEB9"))) {
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
