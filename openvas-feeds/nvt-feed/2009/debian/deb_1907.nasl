# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66053");
  script_cve_id("CVE-2008-5714", "CVE-2009-3290");
  script_tag(name:"creation_date", value:"2009-10-19 19:50:22 +0000 (Mon, 19 Oct 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1907-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1907-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1907-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1907");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kvm' package(s) announced via the DSA-1907-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in kvm, a full virtualization system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-5714

Chris Webb discovered an off-by-one bug limiting KVM's VNC passwords to 7 characters. This flaw might make it easier for remote attackers to guess the VNC password, which is limited to seven characters where eight was intended.

CVE-2009-3290

It was discovered that the kvm_emulate_hypercall function in KVM does not prevent access to MMU hypercalls from ring 0, which allows local guest OS users to cause a denial of service (guest kernel crash) and read or write guest kernel memory.

The oldstable distribution (etch) does not contain kvm.

For the stable distribution (lenny), these problems have been fixed in version 72+dfsg-5~lenny3.

For the testing distribution (squeeze) these problems will be fixed soon.

For the unstable distribution (sid) these problems have been fixed in version 85+dfsg-4.1

We recommend that you upgrade your kvm packages.");

  script_tag(name:"affected", value:"'kvm' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kvm", ver:"72+dfsg-5~lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kvm-source", ver:"72+dfsg-5~lenny3", rls:"DEB5"))) {
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
