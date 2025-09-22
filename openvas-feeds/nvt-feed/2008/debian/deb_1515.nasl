# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60567");
  script_cve_id("CVE-2007-3377", "CVE-2007-3409", "CVE-2007-6341");
  script_tag(name:"creation_date", value:"2008-03-19 19:30:32 +0000 (Wed, 19 Mar 2008)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-03 02:30:09 +0000 (Sat, 03 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1515-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1515-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1515-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1515");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libnet-dns-perl' package(s) announced via the DSA-1515-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in libnet-dns-perl. The Common Vulnerabilities and Exposures project identifies the following problems:

It was discovered that libnet-dns-perl generates very weak transaction IDs when sending queries (CVE-2007-3377). This update switches transaction ID generation to the Perl random generator, making prediction attacks more difficult.

Compression loops in domain names resulted in an infinite loop in the domain name expander written in Perl (CVE-2007-3409). The Debian package uses an expander written in C by default, but this vulnerability has been addressed nevertheless.

Decoding malformed A records could lead to a crash (via an uncaught Perl exception) of certain applications using libnet-dns-perl (CVE-2007-6341).

For the old stable distribution (sarge), these problems have been fixed in version 0.48-1sarge1.

For the stable distribution (etch), these problems have been fixed in version 0.59-1etch1.

We recommend that you upgrade your libnet-dns-perl package.");

  script_tag(name:"affected", value:"'libnet-dns-perl' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libnet-dns-perl", ver:"0.48-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libnet-dns-perl", ver:"0.59-1etch1", rls:"DEB4"))) {
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
