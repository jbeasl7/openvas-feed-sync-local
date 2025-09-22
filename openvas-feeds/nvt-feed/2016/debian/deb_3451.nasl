# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703451");
  script_cve_id("CVE-2016-1233");
  script_tag(name:"creation_date", value:"2016-01-19 23:00:00 +0000 (Tue, 19 Jan 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-29 18:12:52 +0000 (Fri, 29 Jan 2016)");

  script_name("Debian: Security Advisory (DSA-3451-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3451-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3451-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3451");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fuse' package(s) announced via the DSA-3451-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered a vulnerability in the fuse (Filesystem in Userspace) package in Debian. The fuse package ships an udev rule adjusting permissions on the related /dev/cuse character device, making it world writable.

This permits a local, unprivileged attacker to create an arbitrarily-named character device in /dev and modify the memory of any process that opens it and performs an ioctl on it.

This in turn might allow a local, unprivileged attacker to escalate to root privileges.

For the oldstable distribution (wheezy), the fuse package is not affected.

For the stable distribution (jessie), this problem has been fixed in version 2.9.3-15+deb8u2.

For the testing distribution (stretch), this problem has been fixed in version 2.9.5-1.

For the unstable distribution (sid), this problem has been fixed in version 2.9.5-1.

We recommend that you upgrade your fuse packages.");

  script_tag(name:"affected", value:"'fuse' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fuse", ver:"2.9.3-15+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-dbg", ver:"2.9.3-15+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-udeb", ver:"2.9.3-15+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse-dev", ver:"2.9.3-15+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse2", ver:"2.9.3-15+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfuse2-udeb", ver:"2.9.3-15+deb8u2", rls:"DEB8"))) {
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
