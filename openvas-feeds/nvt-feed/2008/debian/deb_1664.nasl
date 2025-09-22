# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61854");
  script_cve_id("CVE-2008-4776");
  script_tag(name:"creation_date", value:"2008-11-19 15:52:57 +0000 (Wed, 19 Nov 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1664-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1664-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1664");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ekg' package(s) announced via the DSA-1664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ekg, a console Gadu Gadu client performs insufficient input sanitising in the code to parse contact descriptions, which may result in denial of service.

For the stable distribution (etch), this problem has been fixed in version 1:1.7~rc2-1etch2.

For the unstable distribution (sid) and the upcoming stable distribution (lenny), this problem has been fixed in version 1:1.8~rc1-2 of libgadu.

We recommend that you upgrade your ekg package.");

  script_tag(name:"affected", value:"'ekg' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ekg", ver:"1:1.7~rc2-1etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu-dev", ver:"1:1.7~rc2-1etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgadu3", ver:"1:1.7~rc2-1etch2", rls:"DEB4"))) {
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
