# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57407");
  script_cve_id("CVE-2005-4798", "CVE-2006-1528", "CVE-2006-2444", "CVE-2006-2446", "CVE-2006-2935", "CVE-2006-3745", "CVE-2006-4535");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1183-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1183-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1183");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, kernel-source-2.4.27, systemimager' package(s) announced via the DSA-1183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in the Linux kernel which may lead to a denial of service or even the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-4798

A buffer overflow in NFS readlink handling allows a malicious remote server to cause a denial of service.

CVE-2006-2935

Diego Calleja Garcia discovered a buffer overflow in the DVD handling code that could be exploited by a specially crafted DVD USB storage device to execute arbitrary code.

CVE-2006-1528

A bug in the SCSI driver allows a local user to cause a denial of service.

CVE-2006-2444

Patrick McHardy discovered a bug in the SNMP NAT helper that allows remote attackers to cause a denial of service.

CVE-2006-2446

A race condition in the socket buffer handling allows remote attackers to cause a denial of service.

CVE-2006-3745

Wei Wang discovered a bug in the SCTP implementation that allows local users to cause a denial of service and possibly gain root privileges.

CVE-2006-4535

David Miller reported a problem with the fix for CVE-2006-3745 that allows local users to crash the system via an SCTP socket with a certain SO_LINGER value.

The following matrix explains which kernel version for which architecture fixes the problem mentioned above:



stable (sarge)

Source

2.4.27-10sarge4

Alpha architecture

2.4.27-10sarge4

ARM architecture

2.4.27-2sarge4

Intel IA-32 architecture

2.4.27-10sarge4

Intel IA-64 architecture

2.4.27-10sarge4

Motorola 680x0 architecture

2.4.27-3sarge4

MIPS architectures

2.4.27-10.sarge4.040815-1

PowerPC architecture

2.4.27-10sarge4

IBM S/390

2.4.27-2sarge4

Sun Sparc architecture

2.4.27-9sarge4

FAI

1.9.1sarge4

mindi-kernel

2.4.27-2sarge3

kernel-image-speakup-i386

2.4.27-1.1sarge3

systemimager

3.2.3-6sarge3

For the unstable distribution (sid) these problems won't be fixed anymore in the 2.4 kernel series.

We recommend that you upgrade your kernel package and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'fai-kernels, kernel-source-2.4.27, systemimager' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fai-kernels", ver:"1.9.1sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.4.27", ver:"2.4.27-10sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"systemimager-boot-i386-standard", ver:"3.2.3-6sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"systemimager-boot-ia64-standard", ver:"3.2.3-6sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"systemimager-client", ver:"3.2.3-6sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"systemimager-common", ver:"3.2.3-6sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"systemimager-doc", ver:"3.2.3-6sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"systemimager-server", ver:"3.2.3-6sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"systemimager-server-flamethrowerd", ver:"3.2.3-6sarge3", rls:"DEB3.1"))) {
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
