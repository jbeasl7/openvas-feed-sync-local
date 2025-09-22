# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62842");
  script_cve_id("CVE-2008-5050", "CVE-2008-5314");
  script_tag(name:"creation_date", value:"2008-12-10 04:23:56 +0000 (Wed, 10 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1680-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1680-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1680-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1680");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'clamav' package(s) announced via the DSA-1680-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moritz Jodeit discovered that ClamAV, an anti-virus solution, suffers from an off-by-one-error in its VBA project file processing, leading to a heap-based buffer overflow and potentially arbitrary code execution (CVE-2008-5050).

Ilja van Sprundel discovered that ClamAV contains a denial of service condition in its JPEG file processing because it does not limit the recursion depth when processing JPEG thumbnails (CVE-2008-5314).

For the stable distribution (etch), these problems have been fixed in version 0.90.1dfsg-4etch16.

For the unstable distribution (sid), these problems have been fixed in version 0.94.dfsg.2-1.

The testing distribution (lenny) will be fixed soon.

We recommend that you upgrade your clamav packages.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"clamav", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-base", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-docs", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-milter", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libclamav2", ver:"0.90.1dfsg-4etch16", rls:"DEB4"))) {
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
