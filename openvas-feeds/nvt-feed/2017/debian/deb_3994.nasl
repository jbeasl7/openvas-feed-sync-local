# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703994");
  script_cve_id("CVE-2017-14604");
  script_tag(name:"creation_date", value:"2017-10-06 22:00:00 +0000 (Fri, 06 Oct 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-05 15:04:53 +0000 (Thu, 05 Oct 2017)");

  script_name("Debian: Security Advisory (DSA-3994-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-3994-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3994-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3994");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nautilus' package(s) announced via the DSA-3994-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Boxdorfer discovered a vulnerability in the handling of FreeDesktop.org .desktop files in Nautilus, a file manager for the GNOME desktop environment. An attacker can craft a .desktop file intended to run malicious commands but displayed as a innocuous document file in Nautilus. An user would then trust it and open the file, and Nautilus would in turn execute the malicious content. Nautilus protection of only trusting .desktop files with executable permission can be bypassed by shipping the .desktop file inside a tarball.

For the oldstable distribution (jessie), this problem has not been fixed yet.

For the stable distribution (stretch), this problem has been fixed in version 3.22.3-1+deb9u1.

For the testing distribution (buster), this problem has been fixed in version 3.26.0-1.

For the unstable distribution (sid), this problem has been fixed in version 3.26.0-1.

We recommend that you upgrade your nautilus packages.");

  script_tag(name:"affected", value:"'nautilus' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-nautilus-3.0", ver:"3.22.3-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnautilus-extension-dev", ver:"3.22.3-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnautilus-extension1a", ver:"3.22.3-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nautilus", ver:"3.22.3-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nautilus-data", ver:"3.22.3-1+deb9u1", rls:"DEB9"))) {
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
