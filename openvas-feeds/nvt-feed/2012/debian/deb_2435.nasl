# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71240");
  script_cve_id("CVE-2010-4337", "CVE-2011-4328", "CVE-2012-1175");
  script_tag(name:"creation_date", value:"2012-04-30 11:54:49 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2435-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2435-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2435");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnash' package(s) announced via the DSA-2435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been identified in Gnash, the GNU Flash player.

CVE-2012-1175

Tielei Wang from Georgia Tech Information Security Center discovered a vulnerability in GNU Gnash which is caused due to an integer overflow error and can be exploited to cause a heap-based buffer overflow by tricking a user into opening a specially crafted SWF file.

CVE-2011-4328

Alexander Kurtz discovered an unsafe management of HTTP cookies. Cookie files are stored under /tmp and have predictable names, and the vulnerability allows a local attacker to overwrite arbitrary files the users has write permissions for, and are also world-readable which may cause information leak.

CVE-2010-4337

Jakub Wilk discovered an unsafe management of temporary files during the build process. Files are stored under /tmp and have predictable names, and the vulnerability allows a local attacker to overwrite arbitrary files the users has write permissions for.

For the stable distribution (squeeze), this problem has been fixed in version 0.8.8-5+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 0.8.10-5.

We recommend that you upgrade your gnash packages.");

  script_tag(name:"affected", value:"'gnash' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"browser-plugin-gnash", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash-common", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash-common-opengl", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash-cygnal", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash-dbg", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash-doc", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash-opengl", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnash-tools", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"klash", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"klash-opengl", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror-plugin-gnash", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-plugin-gnash", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"swfdec-gnome", ver:"1:0.8.8-5+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"swfdec-mozilla", ver:"0.8.8-5+squeeze1", rls:"DEB6"))) {
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
