# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60444");
  script_cve_id("CVE-2008-0411");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1510-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1510-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1510-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1510");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gs-esp, gs-gpl' package(s) announced via the DSA-1510-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered a buffer overflow in the color space handling code of the Ghostscript PostScript/PDF interpreter, which might result in the execution of arbitrary code if a user is tricked into processing a malformed file.

For the stable distribution (etch), this problem has been fixed in version 8.54.dfsg.1-5etch1 of gs-gpl and 8.15.3.dfsg.1-1etch1 of gs-esp.

For the old stable distribution (sarge), this problem has been fixed in version 8.01-6 of gs-gpl and 7.07.1-9sarge1 of gs-esp.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your gs-esp and gs-gpl packages.");

  script_tag(name:"affected", value:"'gs-esp, gs-gpl' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gs", ver:"8.01-6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-esp", ver:"7.07.1-9sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-gpl", ver:"8.01-6", rls:"DEB3.1"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gs", ver:"8.54.dfsg.1-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-esp", ver:"8.15.3.dfsg.1-1etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gs-gpl", ver:"8.54.dfsg.1-5etch1", rls:"DEB4"))) {
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
