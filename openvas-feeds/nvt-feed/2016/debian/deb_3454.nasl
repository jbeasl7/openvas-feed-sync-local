# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703454");
  script_cve_id("CVE-2015-5307", "CVE-2015-8104", "CVE-2016-0495", "CVE-2016-0592");
  script_tag(name:"creation_date", value:"2016-01-26 23:00:00 +0000 (Tue, 26 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3454-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3454-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3454-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3454");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'virtualbox' package(s) announced via the DSA-3454-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in VirtualBox, an x86 virtualisation solution.

Upstream support for the 4.1 release series has ended and since no information is available which would allow backports of isolated security fixes, security support for virtualbox in wheezy/oldstable needed to be ended as well. If you use virtualbox with externally procured VMs (e.g. through vagrant) we advise you to update to Debian jessie.

For the stable distribution (jessie), these problems have been fixed in version 4.3.36-dfsg-1+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 5.0.14-dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 5.0.14-dfsg-1.

We recommend that you upgrade your virtualbox packages.");

  script_tag(name:"affected", value:"'virtualbox' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-dbg", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-dkms", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-dkms", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-source", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-utils", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-guest-x11", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-qt", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtualbox-source", ver:"4.3.36-dfsg-1+deb8u1", rls:"DEB8"))) {
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
