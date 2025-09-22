# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703897");
  script_cve_id("CVE-2017-6922");
  script_tag(name:"creation_date", value:"2017-06-23 22:00:00 +0000 (Fri, 23 Jun 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-13 16:35:42 +0000 (Wed, 13 Feb 2019)");

  script_name("Debian: Security Advisory (DSA-3897-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-3897-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3897-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3897");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2015-004");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2017-003");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal7' package(s) announced via the DSA-3897-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Drupal, a fully-featured content management framework. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2015-7943

Samuel Mortenson and Pere Orga discovered that the overlay module does not sufficiently validate URLs prior to displaying their contents, leading to an open redirect vulnerability.

More information can be found at [link moved to references]

CVE-2017-6922

Greg Knaddison, Mori Sugimoto and iancawthorne discovered that files uploaded by anonymous users into a private file system can be accessed by other anonymous users leading to an access bypass vulnerability.

More information can be found at [link moved to references]

For the oldstable distribution (jessie), these problems have been fixed in version 7.32-1+deb8u9.

For the stable distribution (stretch), these problems have been fixed in version 7.52-2+deb9u1. For the stable distribution (stretch), CVE-2015-7943 was already fixed before the initial release.

We recommend that you upgrade your drupal7 packages.");

  script_tag(name:"affected", value:"'drupal7' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.32-1+deb8u9", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"drupal7", ver:"7.52-2+deb9u1", rls:"DEB9"))) {
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
