# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72172");
  script_cve_id("CVE-2012-3515", "CVE-2012-4411");
  script_tag(name:"creation_date", value:"2012-09-15 08:24:00 +0000 (Sat, 15 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2543-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2543-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2543-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2543");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen-qemu-dm-4.0' package(s) announced via the DSA-2543-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in xen-qemu-dm-4.0, the Xen QEMU Device Model virtual machine hardware emulator. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-3515: The device model for HVM domains does not properly handle VT100 escape sequences when emulating certain devices with a virtual console backend. An attacker within a guest with access to the vulnerable virtual console could overwrite memory of the device model and escalate privileges to that of the device model process.

CVE-2012-4411: The QEMU monitor was enabled by default, allowing administrators of a guest to access resources of the host, possibly escalate privileges or access resources belonging to another guest.

For the stable distribution (squeeze), these problems have been fixed in version 4.0.1-2+squeeze2.

The testing distribution (wheezy), and the unstable distribution (sid), no longer contain this package.

We recommend that you upgrade your xen-qemu-dm-4.0 packages.");

  script_tag(name:"affected", value:"'xen-qemu-dm-4.0' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xen-qemu-dm-4.0", ver:"4.0.1-2+squeeze2", rls:"DEB6"))) {
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
