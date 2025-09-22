# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60210");
  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
  script_tag(name:"creation_date", value:"2008-01-31 15:11:48 +0000 (Thu, 31 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1466-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1466-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1466-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1466");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xfree86, xorg-server' package(s) announced via the DSA-1466-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The X.org fix for CVE-2007-6429 introduced a regression in the MIT-SHM extension, which prevented the start of a few applications. This update provides updated packages for the xfree86 version included in Debian old stable (sarge) in addition to the fixed packages for Debian stable (etch), which were provided in DSA 1466-2.

For reference the original advisory text below:

Several local vulnerabilities have been discovered in the X.Org X server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5760

regenrecht discovered that missing input sanitising within the XFree86-Misc extension may lead to local privilege escalation.

CVE-2007-5958

It was discovered that error messages of security policy file handling may lead to a minor information leak disclosing the existence of files otherwise inaccessible to the user.

CVE-2007-6427

regenrecht discovered that missing input sanitising within the XInput-Misc extension may lead to local privilege escalation.

CVE-2007-6428

regenrecht discovered that missing input sanitising within the TOG-CUP extension may lead to disclosure of memory contents.

CVE-2007-6429

regenrecht discovered that integer overflows in the EVI and MIT-SHM extensions may lead to local privilege escalation.

CVE-2008-0006

It was discovered that insufficient validation of PCF fonts could lead to local privilege escalation.

For the oldstable distribution (sarge), this problem has been fixed in version 4.3.0.dfsg.1-14sarge7 of xfree86.

For the stable distribution (etch), this problem has been fixed in version 1.1.1-21etch3 of xorg-server and 1.2.2-2.etch1 of libxfont.

For the unstable distribution (sid), this problem has been fixed in version 2:1.4.1~git20080118-1 of xorg-server and version 1:1.3.1-2 of libxfont.

We recommend that you upgrade your X.org/Xfree86 packages.");

  script_tag(name:"affected", value:"'xfree86, xorg-server' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lbxproxy", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdps-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdps1", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdps1-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libice-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libice6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libice6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsm-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsm6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsm6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx11-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw6-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw7", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw7-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxaw7-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxext-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxext6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxext6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxft1", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxft1-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxi-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxi6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxi6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmu-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmu6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmu6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmuu-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmuu1", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxmuu1-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxp-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxp6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxp6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxrandr-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxrandr2", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxrandr2-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxt-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxt6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxt6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtrap-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtrap6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtrap6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtst-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtst6", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxtst6-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxv-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxv1", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxv1-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pm-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proxymngr", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"twm", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-window-system", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-window-system-core", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"x-window-system-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xbase-clients", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xdm", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-100dpi", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-100dpi-transcoded", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-75dpi", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-75dpi-transcoded", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-base", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-base-transcoded", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-cyrillic", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-scalable", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfree86-common", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfwp", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-dri", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-dri-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-gl", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-gl-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-gl-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-glu", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-glu-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa-glu-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa3", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibmesa3-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibosmesa-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibosmesa4", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibosmesa4-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-data", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-pic", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-static-dev", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xlibs-static-pic", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xmh", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xnest", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-common", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xfree86", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xfree86-dbg", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xspecs", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xterm", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xutils", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xvfb", ver:"4.3.0.dfsg.1-14sarge7", rls:"DEB3.1"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xdmx", ver:"2:1.1.1-21etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xdmx-tools", ver:"2:1.1.1-21etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xnest", ver:"2:1.1.1-21etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xephyr", ver:"2:1.1.1-21etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.1.1-21etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"2:1.1.1-21etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xvfb", ver:"2:1.1.1-21etch3", rls:"DEB4"))) {
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
