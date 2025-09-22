# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70701");
  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837", "CVE-2011-3145");
  script_tag(name:"creation_date", value:"2012-02-11 08:26:49 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-29 16:24:45 +0000 (Mon, 29 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-2382-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2382-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2382-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2382");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ecryptfs-utils' package(s) announced via the DSA-2382-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several problems have been discovered in eCryptfs, a cryptographic filesystem for Linux.

CVE-2011-1831

Vasiliy Kulikov of Openwall and Dan Rosenberg discovered that eCryptfs incorrectly validated permissions on the requested mountpoint. A local attacker could use this flaw to mount to arbitrary locations, leading to privilege escalation.

CVE-2011-1832

Vasiliy Kulikov of Openwall and Dan Rosenberg discovered that eCryptfs incorrectly validated permissions on the requested mountpoint. A local attacker could use this flaw to unmount to arbitrary locations, leading to a denial of service.

CVE-2011-1834

Dan Rosenberg and Marc Deslauriers discovered that eCryptfs incorrectly handled modifications to the mtab file when an error occurs. A local attacker could use this flaw to corrupt the mtab file, and possibly unmount arbitrary locations, leading to a denial of service.

CVE-2011-1835

Marc Deslauriers discovered that eCryptfs incorrectly handled keys when setting up an encrypted private directory. A local attacker could use this flaw to manipulate keys during creation of a new user.

CVE-2011-1837

Vasiliy Kulikov of Openwall discovered that eCryptfs incorrectly handled lock counters. A local attacker could use this flaw to possibly overwrite arbitrary files.

We acknowledge the work of the Ubuntu distribution in preparing patches suitable for near-direct inclusion in the Debian package.

For the oldstable distribution (lenny), these problems have been fixed in version 68-1+lenny1.

For the stable distribution (squeeze), these problems have been fixed in version 83-4+squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 95-1.

We recommend that you upgrade your ecryptfs-utils packages.");

  script_tag(name:"affected", value:"'ecryptfs-utils' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"68-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecryptfs-dev", ver:"68-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecryptfs0", ver:"68-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"ecryptfs-utils", ver:"83-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ecryptfs-utils-dbg", ver:"83-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecryptfs-dev", ver:"83-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecryptfs0", ver:"83-4+squeeze1", rls:"DEB6"))) {
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
