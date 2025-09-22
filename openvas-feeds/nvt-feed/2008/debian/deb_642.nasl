# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53744");
  script_cve_id("CVE-2004-1106");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-642-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-642-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-642-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-642");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gallery' package(s) announced via the DSA-642-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in gallery, a web-based photo album written in PHP4. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2004-1106

Jim Paris discovered a cross site scripting vulnerability which allows code to be inserted by using specially formed URLs.

CVE-NOMATCH The upstream developers of gallery have fixed several cases of possible variable injection that could trick gallery to unintended actions, e.g. leaking database passwords.

For the stable distribution (woody) these problems have been fixed in version 1.2.5-8woody3.

For the unstable distribution (sid) these problems have been fixed in version 1.4.4-pl4-1.

We recommend that you upgrade your gallery package.");

  script_tag(name:"affected", value:"'gallery' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gallery", ver:"1.2.5-8woody3", rls:"DEB3.0"))) {
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
