# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68986");
  script_cve_id("CVE-2011-0015", "CVE-2011-0016", "CVE-2011-0427", "CVE-2011-0490", "CVE-2011-0491", "CVE-2011-0492", "CVE-2011-0493");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2148-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2148-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2148");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/source-package/tor");
  script_xref(name:"URL", value:"https://www.debian.org/security/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tor' package(s) announced via the DSA-2148-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The developers of Tor, an anonymizing overlay network for TCP, found three security issues during a security audit. A heap overflow allowed the execution of arbitrary code (CVE-2011-0427), a denial of service vulnerability was found in the zlib compression handling and some key memory was incorrectly zeroed out before being freed. The latter two issues do not yet have CVE identifiers assigned. The Debian Security Tracker will be updated once they're available: [link moved to references]

For the stable distribution (lenny), this problem has been fixed in version 0.2.1.29-1~lenny+1.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 0.2.1.29-1.

For the experimental distribution, this problem has been fixed in version 0.2.2.21-alpha-1.

We recommend that you upgrade your tor packages.

Further information about Debian Security Advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'tor' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"tor", ver:"0.2.1.29-1~lenny+1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.1.29-1~lenny+1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.1.29-1~lenny+1", rls:"DEB5"))) {
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
