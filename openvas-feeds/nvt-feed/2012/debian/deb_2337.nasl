# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70551");
  script_cve_id("CVE-2011-1166", "CVE-2011-1583", "CVE-2011-1898", "CVE-2011-3262");
  script_tag(name:"creation_date", value:"2012-02-11 07:27:52 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2337-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2337-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2337-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2337");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-2337-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Xen virtual machine hypervisor.

CVE-2011-1166

A 64-bit guest can get one of its vCPUs into non-kernel mode without first providing a valid non-kernel pagetable, thereby locking up the host system.

CVE-2011-1583, CVE-2011-3262 Local users can cause a denial of service and possibly execute arbitrary code via a crafted paravirtualised guest kernel image.

CVE-2011-1898

When using PCI passthrough on Intel VT-d chipsets that do not have interrupt remapping, guest OS users can gain host OS privileges by writing to the interrupt injection registers.

The oldstable distribution (lenny) contains a different version of Xen not affected by these problems.

For the stable distribution (squeeze), this problem has been fixed in version 4.0.1-4.

For the testing (wheezy) and unstable distribution (sid), this problem has been fixed in version 4.1.1-1.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.0.1-4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.0.1-4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-docs-4.0", ver:"4.0.1-4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.0-amd64", ver:"4.0.1-4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.0-i386", ver:"4.0.1-4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.0", ver:"4.0.1-4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.0.1-4", rls:"DEB6"))) {
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
