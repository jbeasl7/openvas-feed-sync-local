# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57736");
  script_cve_id("CVE-2006-4093", "CVE-2006-4538", "CVE-2006-4997", "CVE-2006-5174", "CVE-2006-5649", "CVE-2006-5871");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-08-04T05:47:09+0000");
  script_tag(name:"last_modification", value:"2025-08-04 05:47:09 +0000 (Mon, 04 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-10 02:45:17 +0000 (Sat, 10 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1237-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1237-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1237-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1237");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-source-2.4.27' package(s) announced via the DSA-1237-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-4093

Olof Johansson reported a local DoS (Denial of Service) vulnerability on the PPC970 platform. Unprivileged users can hang the system by executing the attn instruction, which was not being disabled at boot.

CVE-2006-4538

Kirill Korotaev reported a local DoS (Denial of Service) vulnerability on the ia64 and sparc architectures. A user could cause the system to crash by executing a malformed ELF binary due to insufficient verification of the memory layout.

CVE-2006-4997

ADLab Venustech Info Ltd reported a potential remote DoS (Denial of Service) vulnerability in the IP over ATM subsystem. A remote system could cause the system to crash by sending specially crafted packets that would trigger an attempt to free an already-freed pointer resulting in a system crash.

CVE-2006-5174

Martin Schwidefsky reported a potential leak of sensitive information on s390 systems. The copy_from_user function did not clear the remaining bytes of the kernel buffer after receiving a fault on the userspace address, resulting in a leak of uninitialized kernel memory. A local user could exploit this by appending to a file from a bad address.

CVE-2006-5649

Fabio Massimo Di Nitto reported a potential remote DoS (Denial of Service) vulnerability on powerpc systems. The alignment exception only checked the exception table for -EFAULT, not for other errors. This can be exploited by a local user to cause a system crash (panic).

CVE-2006-5871

Bill Allombert reported that various mount options are ignored by smbfs when UNIX extensions are enabled. This includes the uid, gid and mode options. Client systems would silently use the server-provided settings instead of honoring these options, changing the security model. This update includes a fix from Haroldo Gamal that forces the kernel to honor these mount options. Note that, since the current versions of smbmount always pass values for these options to the kernel, it is not currently possible to activate unix extensions by omitting mount options. However, this behavior is currently consistent with the current behavior of the next Debian release, 'etch'.

The following matrix explains which kernel version for which architecture fix the problems mentioned above:

Debian 3.1 (sarge)

Source 2.4.27-10sarge5

Alpha architecture 2.4.27-10sarge5

ARM architecture 2.4.27-2sarge5

Intel IA-32 architecture 2.4.27-10sarge5

Intel IA-64 architecture 2.4.27-10sarge5

Motorola 680x0 architecture 2.4.27-3sarge5

Big endian MIPS 2.4.27-10.sarge4.040815-2

Little endian MIPS 2.4.27-10.sarge4.040815-2

PowerPC architecture 2.4.27-10sarge5

IBM S/390 architecture 2.4.27-2sarge5

Sun Sparc architecture ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-source-2.4.27' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.4.27", ver:"2.4.27-10sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.4.27", ver:"2.4.27-10sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.4.27", ver:"2.4.27-10sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.4.27", ver:"2.4.27-10sarge5", rls:"DEB3.1"))) {
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
