# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703317");
  script_cve_id("CVE-2015-1331", "CVE-2015-1334");
  script_tag(name:"creation_date", value:"2015-07-24 22:00:00 +0000 (Fri, 24 Jul 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");

  script_name("Debian: Security Advisory (DSA-3317-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3317-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3317-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3317");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lxc' package(s) announced via the DSA-3317-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in LXC, the Linux Containers userspace tools. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-1331

Roman Fiedler discovered a directory traversal flaw in LXC when creating lock files. A local attacker could exploit this flaw to create an arbitrary file as the root user.

CVE-2015-1334

Roman Fiedler discovered that LXC incorrectly trusted the container's proc filesystem to set up AppArmor profile changes and SELinux domain transitions. A malicious container could create a fake proc filesystem and use this flaw to run programs inside the container that are not confined by AppArmor or SELinux.

For the stable distribution (jessie), these problems have been fixed in version 1:1.0.6-6+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 1:1.0.7-4.

For the unstable distribution (sid), these problems have been fixed in version 1:1.0.7-4.

We recommend that you upgrade your lxc packages.");

  script_tag(name:"affected", value:"'lxc' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lxc", ver:"1:1.0.6-6+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxc-dbg", ver:"1:1.0.6-6+deb8u1", rls:"DEB8"))) {
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
