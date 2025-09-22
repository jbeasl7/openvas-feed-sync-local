# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703268");
  script_cve_id("CVE-2015-3202");
  script_tag(name:"creation_date", value:"2015-05-21 22:00:00 +0000 (Thu, 21 May 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3268-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3268-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3268-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3268");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntfs-3g' package(s) announced via the DSA-3268-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that NTFS-3G, a read-write NTFS driver for FUSE, does not scrub the environment before executing mount or umount with elevated privileges. A local user can take advantage of this flaw to overwrite arbitrary files and gain elevated privileges by accessing debugging features via the environment that would not normally be safe for unprivileged users.

For the oldstable distribution (wheezy), this problem has been fixed in version 1:2012.1.15AR.5-2.1+deb7u1. Note that this issue does not affect the binary packages distributed in Debian in wheezy as ntfs-3g does not use the embedded fuse-lite library.

For the stable distribution (jessie), this problem has been fixed in version 1:2014.2.15AR.2-1+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your ntfs-3g packages.");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2012.1.15AR.5-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dbg", ver:"1:2012.1.15AR.5-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dev", ver:"1:2012.1.15AR.5-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-udeb", ver:"1:2012.1.15AR.5-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfsprogs", ver:"1:2012.1.15AR.5-2.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2014.2.15AR.2-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dbg", ver:"1:2014.2.15AR.2-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dev", ver:"1:2014.2.15AR.2-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-udeb", ver:"1:2014.2.15AR.2-1+deb8u2", rls:"DEB8"))) {
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
