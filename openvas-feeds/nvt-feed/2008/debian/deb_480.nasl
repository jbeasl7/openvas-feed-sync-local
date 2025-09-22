# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53683");
  script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-480");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-480");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-480");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-image-2.4.17-hppa, kernel-image-2.4.18-hppa' package(s) announced via the DSA-480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several serious problems have been discovered in the Linux kernel. This update takes care of Linux 2.4.17 and 2.4.18 for the hppa (PA-RISC) architecture. The Common Vulnerabilities and Exposures project identifies the following problems that will be fixed with this update:

CAN-2004-0003

A vulnerability has been discovered in the R128 DRI driver in the Linux kernel which could potentially lead an attacker to gain unauthorised privileges. Alan Cox and Thomas Biege developed a correction for this.

CAN-2004-0010

Arjan van de Ven discovered a stack-based buffer overflow in the ncp_lookup function for ncpfs in the Linux kernel, which could lead an attacker to gain unauthorised privileges. Petr Vandrovec developed a correction for this.

CAN-2004-0109

zen-parse discovered a buffer overflow vulnerability in the ISO9660 filesystem component of Linux kernel which could be abused by an attacker to gain unauthorised root access. Sebastian Krahmer and Ernie Petrides developed a correction for this.

CAN-2004-0177

Solar Designer discovered an information leak in the ext3 code of Linux. In a worst case an attacker could read sensitive data such as cryptographic keys which would otherwise never hit disk media. Theodore Ts'o developed a correction for this.

CAN-2004-0178

Andreas Kies discovered a denial of service condition in the Sound Blaster driver in Linux. He also developed a correction for this.

These problems are also fixed by upstream in Linux 2.4.26 and will be fixed in Linux 2.6.6.

For the stable distribution (woody) these problems have been fixed in version 32.4 for Linux 2.4.17 and in version 62.3 for Linux 2.4.18.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your kernel packages immediately, either with a Debian provided kernel or with a self compiled one.

Vulnerability matrix for CAN-2004-0109");

  script_tag(name:"affected", value:"'kernel-image-2.4.17-hppa, kernel-image-2.4.18-hppa' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.4.17-hppa", ver:"32.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.4.18-hppa", ver:"62.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.17-32", ver:"32.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.17-32-smp", ver:"32.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.17-64", ver:"32.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.17-64-smp", ver:"32.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.18-32", ver:"62.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.18-32-smp", ver:"62.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.18-64", ver:"62.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.18-64-smp", ver:"62.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.4.17-hppa", ver:"32.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.4.18-hppa", ver:"62.3", rls:"DEB3.0"))) {
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
