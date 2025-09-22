# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62954");
  script_cve_id("CVE-2008-5316", "CVE-2008-5317");
  script_tag(name:"creation_date", value:"2008-12-23 17:28:16 +0000 (Tue, 23 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1684-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1684-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1684-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1684");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lcms' package(s) announced via the DSA-1684-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been found in lcms, a library and set of commandline utilities for image color management. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-5316

Inadequate enforcement of fixed-length buffer limits allows an attacker to overflow a buffer on the stack, potentially enabling the execution of arbitrary code when a maliciously-crafted image is opened.

CVS-2008-5317

An integer sign error in reading image gamma data could allow an attacker to cause an under-sized buffer to be allocated for subsequent image data, with unknown consequences potentially including the execution of arbitrary code if a maliciously-crafted image is opened.

For the stable distribution (etch), these problems have been fixed in version 1.15-1.1+etch1.

For the upcoming stable distribution (lenny), and the unstable distribution (sid), these problems are fixed in version 1.17.dfsg-1.

We recommend that you upgrade your lcms packages.");

  script_tag(name:"affected", value:"'lcms' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblcms-utils", ver:"1.15-1.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms1", ver:"1.15-1.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms1-dev", ver:"1.15-1.1+etch1", rls:"DEB4"))) {
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
