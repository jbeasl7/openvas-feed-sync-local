# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58613");
  script_cve_id("CVE-2007-2438", "CVE-2007-2953");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1364-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1364-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1364-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1364");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vim' package(s) announced via the DSA-1364-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the vim editor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2953

Ulf Harnhammar discovered that a format string flaw in helptags_one() from src/ex_cmds.c (triggered through the helptags command) can lead to the execution of arbitrary code.

CVE-2007-2438

Editors often provide a way to embed editor configuration commands (aka modelines) which are executed once a file is opened. Harmful commands are filtered by a sandbox mechanism. It was discovered that function calls to writefile(), feedkeys() and system() were not filtered, allowing shell command execution with a carefully crafted file opened in vim.

This updated advisory repairs issues with missing files in the packages for the oldstable distribution (sarge) for the alpha, mips, and mipsel architectures.

For the oldstable distribution (sarge) these problems have been fixed in version 6.3-071+1sarge2. Sarge is not affected by CVE-2007-2438.

For the stable distribution (etch) these problems have been fixed in version 7.0-122+1etch3.

For the unstable distribution (sid) these problems have been fixed in version 7.1-056+1.

We recommend that you upgrade your vim packages.");

  script_tag(name:"affected", value:"'vim' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-common", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-doc", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-full", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gnome", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gui-common", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-lesstif", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-perl", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-python", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-ruby", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-runtime", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tcl", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"1:7.0-122+1etch3", rls:"DEB4"))) {
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
