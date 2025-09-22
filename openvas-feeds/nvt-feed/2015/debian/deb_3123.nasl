# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703123");
  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_tag(name:"creation_date", value:"2015-01-08 23:00:00 +0000 (Thu, 08 Jan 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3123-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3123-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3123-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3123");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'binutils-mingw-w64' package(s) announced via the DSA-3123-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in binutils, a toolbox for binary file manipulation. These vulnerabilities include multiple memory safety errors, buffer overflows, use-after-frees and other implementation errors may lead to the execution of arbitrary code, the bypass of security restrictions, path traversal attack or denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 2.22-8+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 2.25-3.

We recommend that you upgrade your binutils packages.");

  script_tag(name:"affected", value:"'binutils-mingw-w64' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"binutils-mingw-w64", ver:"2.22-8+deb7u2+2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-mingw-w64-i686", ver:"2.22-8+deb7u2+2+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-mingw-w64-x86-64", ver:"2.22-8+deb7u2+2+deb7u1", rls:"DEB7"))) {
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
