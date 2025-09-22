# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63995");
  script_cve_id("CVE-2008-0928", "CVE-2008-1945", "CVE-2008-4539");
  script_tag(name:"creation_date", value:"2009-05-19 22:17:15 +0000 (Tue, 19 May 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1799-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1799-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1799-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1799");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-1799-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the QEMU processor emulator. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0928

Ian Jackson discovered that range checks of file operations on emulated disk devices were insufficiently enforced.

CVE-2008-1945

It was discovered that an error in the format auto detection of removable media could lead to the disclosure of files in the host system.

CVE-2008-4539

A buffer overflow has been found in the emulation of the Cirrus graphics adaptor.

For the old stable distribution (etch), these problems have been fixed in version 0.8.2-4etch3.

For the stable distribution (lenny), these problems have been fixed in version 0.9.1-10lenny1.

For the unstable distribution (sid), these problems have been fixed in version 0.9.1+svn20081101-1.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 4, Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"0.8.2-4etch3", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"0.9.1-10lenny1", rls:"DEB5"))) {
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
