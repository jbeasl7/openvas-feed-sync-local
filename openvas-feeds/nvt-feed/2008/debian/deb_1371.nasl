# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58594");
  script_cve_id("CVE-2007-2024", "CVE-2007-2025", "CVE-2007-3193");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1371-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1371-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1371-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1371");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpwiki' package(s) announced via the DSA-1371-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in phpWiki, a wiki engine written in PHP. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2024

It was discovered that phpWiki performs insufficient file name validation, which allows unrestricted file uploads.

CVE-2007-2025

It was discovered that phpWiki performs insufficient file name validation, which allows unrestricted file uploads.

CVE-2007-3193

If the configuration lacks a nonzero PASSWORD_LENGTH_MINIMUM, phpWiki might allow remote attackers to bypass authentication via an empty password, which causes ldap_bind to return true when used with certain LDAP implementations.

The old stable distribution (sarge) does not contain phpwiki packages.

For the stable distribution (etch) these problems have been fixed in version 1.3.12p3-5etch1.

For the unstable distribution (sid) these problems have been fixed in version 1.3.12p3-6.1.

We recommend that you upgrade your phpwiki package.");

  script_tag(name:"affected", value:"'phpwiki' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"phpwiki", ver:"1.3.12p3-5etch1", rls:"DEB4"))) {
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
