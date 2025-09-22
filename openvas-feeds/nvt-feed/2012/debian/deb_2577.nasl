# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72627");
  script_cve_id("CVE-2012-4559", "CVE-2012-4561", "CVE-2012-4562", "CVE-2012-6063");
  script_tag(name:"creation_date", value:"2012-12-04 16:43:00 +0000 (Tue, 04 Dec 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2577-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2577-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2577-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2577");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh' package(s) announced via the DSA-2577-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in libssh by Florian Weimer and Xi Wang:

CVE-2012-4559: multiple double free() flaws

CVE-2012-4561: multiple invalid free() flaws

CVE-2012-4562: multiple improper overflow checks

Those could lead to a denial of service by making an SSH client linked to libssh crash, and maybe even arbitrary code execution.

For the stable distribution (squeeze), these problems have been fixed in version 0.4.5-3+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in version 0.5.3-1.

For the unstable distribution (sid), these problems have been fixed in version 0.5.3-1.

We recommend that you upgrade your libssh packages.");

  script_tag(name:"affected", value:"'libssh' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libssh-4", ver:"0.4.5-3+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-dbg", ver:"0.4.5-3+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-dev", ver:"0.4.5-3+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh-doc", ver:"0.4.5-3+squeeze1", rls:"DEB6"))) {
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
