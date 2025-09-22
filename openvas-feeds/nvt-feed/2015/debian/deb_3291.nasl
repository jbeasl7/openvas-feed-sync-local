# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703291");
  script_cve_id("CVE-2015-3231", "CVE-2015-3232", "CVE-2015-3233", "CVE-2015-3234");
  script_tag(name:"creation_date", value:"2015-06-17 22:00:00 +0000 (Wed, 17 Jun 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3291-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3291-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3291-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3291");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-3291-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in drupal7, a content management platform used to power websites.

CVE-2015-3231

Incorrect cache handling made private content viewed by user 1 exposed to other, non-privileged users.

CVE-2015-3232

A flaw in the Field UI module made it possible for attackers to redirect users to malicious sites.

CVE-2015-3233

Due to insufficient URL validation, the Overlay module could be used to redirect users to malicious sites.

CVE-2015-3234

The OpenID module allowed an attacker to log in as other users, including administrators.

For the oldstable distribution (wheezy), these problems have been fixed in version 7.14-2+deb7u10.

For the stable distribution (jessie), these problems have been fixed in version 7.32-1+deb8u4.

For the unstable distribution (sid), these problems have been fixed in version 7.38.1.

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

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.14-2+deb7u10", rls:"DEB7"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.32-1+deb8u4", rls:"DEB8"))) {
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
