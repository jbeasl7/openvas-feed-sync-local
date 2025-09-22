# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56397");
  script_cve_id("CVE-2005-3185", "CVE-2005-4077");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-919-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-919-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-919-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-919");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-919-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The upstream developer of curl, a multi-protocol file transfer library, informed us that the former correction to several off-by-one errors are not sufficient. For completeness please find the original bug description below:

Several problems were discovered in libcurl, a multi-protocol file transfer library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-3185

A buffer overflow has been discovered in libcurl that could allow the execution of arbitrary code.

CVE-2005-4077

Stefan Esser discovered several off-by-one errors that allows local users to trigger a buffer overflow and cause a denial of service or bypass PHP security restrictions via certain URLs.

For the old stable distribution (woody) these problems have been fixed in version 7.9.5-1woody2.

For the stable distribution (sarge) these problems have been fixed in version 7.13.2-2sarge5. This update also includes a bugfix against data corruption.

For the unstable distribution (sid) these problems have been fixed in version 7.15.1-1.

We recommend that you upgrade your libcurl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 3.0, Debian 3.1.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.9.5-1woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl-dev", ver:"7.9.5-1woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl2", ver:"7.9.5-1woody2", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"curl", ver:"7.13.2-2sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.13.2-2sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.13.2-2sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-dev", ver:"7.13.2-2sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gssapi", ver:"7.13.2-2sarge5", rls:"DEB3.1"))) {
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
