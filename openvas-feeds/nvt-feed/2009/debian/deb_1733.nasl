# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63500");
  script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101");
  script_tag(name:"creation_date", value:"2009-03-07 20:47:03 +0000 (Sat, 07 Mar 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1733-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1733-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1733-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1733");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vim' package(s) announced via the DSA-1733-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in vim, an enhanced vi editor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-2712

Jan Minar discovered that vim did not properly sanitise inputs before invoking the execute or system functions inside vim scripts. This could lead to the execution of arbitrary code.

CVE-2008-3074

Jan Minar discovered that the tar plugin of vim did not properly sanitise the filenames in the tar archive or the name of the archive file itself, making it prone to arbitrary code execution.

CVE-2008-3075

Jan Minar discovered that the zip plugin of vim did not properly sanitise the filenames in the zip archive or the name of the archive file itself, making it prone to arbitrary code execution.

CVE-2008-3076

Jan Minar discovered that the netrw plugin of vim did not properly sanitise the filenames or directory names it is given. This could lead to the execution of arbitrary code.

CVE-2008-4101

Ben Schmidt discovered that vim did not properly escape characters when performing keyword or tag lookups. This could lead to the execution of arbitrary code.

For the oldstable distribution (etch), these problems have been fixed in version 1:7.0-122+1etch5.

For the stable distribution (lenny), these problems have been fixed in version 1:7.1.314-3+lenny1, which was already included in the lenny release.

For the testing distribution (squeeze), these problems have been fixed in version 1:7.1.314-3+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 2:7.2.010-1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-common", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-doc", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-full", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gnome", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gui-common", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-lesstif", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-perl", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-python", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-ruby", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-runtime", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tcl", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"1:7.0-122+1etch5", rls:"DEB4"))) {
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
