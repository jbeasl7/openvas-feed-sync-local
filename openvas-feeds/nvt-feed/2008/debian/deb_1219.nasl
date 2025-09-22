# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57654");
  script_cve_id("CVE-2005-3011", "CVE-2006-4810");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-08-04T05:47:09+0000");
  script_tag(name:"last_modification", value:"2025-08-04 05:47:09 +0000 (Mon, 04 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1219-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1219-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1219-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1219");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'texinfo' package(s) announced via the DSA-1219-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the GNU texinfo package, a documentation system for on-line information and printed output.

CVE-2005-3011

Handling of temporary files is performed in an insecure manner, allowing an attacker to overwrite any file writable by the victim.

CVE-2006-4810

A buffer overflow in util/texindex.c could allow an attacker to execute arbitrary code with the victim's access rights by inducing the victim to run texindex or tex2dvi on a specially crafted texinfo file.

For the stable distribution (sarge), these problems have been fixed in version 4.7-2.2sarge2. Note that binary packages for the mipsel architecture are not currently available due to technical problems with the build host. These packages will be made available as soon as possible.

For unstable (sid) and the upcoming stable release (etch), these problems have been fixed in version 4.8.dfsg.1-4.

We recommend that you upgrade your texinfo package.");

  script_tag(name:"affected", value:"'texinfo' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"info", ver:"4.7-2.2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"texinfo", ver:"4.7-2.2sarge2", rls:"DEB3.1"))) {
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
