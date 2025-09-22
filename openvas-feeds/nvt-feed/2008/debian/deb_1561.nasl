# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60866");
  script_cve_id("CVE-2008-1293");
  script_tag(name:"creation_date", value:"2008-04-30 17:28:13 +0000 (Wed, 30 Apr 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1561-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1561-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1561-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1561");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ltsp' package(s) announced via the DSA-1561-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Herzog discovered that within the Linux Terminal Server Project, it was possible to connect to X on any LTSP client from any host on the network, making client windows and keystrokes visible to that host.

NOTE: most ldm installs are likely to be in a chroot environment exported over NFS, and will not be upgraded merely by upgrading the server itself. For example, on the i386 architecture, to upgrade ldm will likely require:

chroot /opt/ltsp/i386 apt-get update chroot /opt/ltsp/i386 apt-get dist-upgrade

For the stable distribution (etch), this problem has been fixed in version 0.99debian11+etch1.

For the unstable distribution (sid), this problem has been fixed in version 2:0.1~bzr20080308-1.

We recommend that you upgrade your ldm package.");

  script_tag(name:"affected", value:"'ltsp' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ldm", ver:"0.99debian11+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ltsp-client", ver:"0.99debian11+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ltsp-client-builder", ver:"0.99debian11+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ltsp-server", ver:"0.99debian11+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ltsp-server-standalone", ver:"0.99debian11+etch1", rls:"DEB4"))) {
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
