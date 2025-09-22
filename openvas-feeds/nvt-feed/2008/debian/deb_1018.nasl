# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56533");
  script_cve_id("CVE-2004-0887", "CVE-2004-1058", "CVE-2004-2607", "CVE-2005-0449", "CVE-2005-1761", "CVE-2005-2457", "CVE-2005-2555", "CVE-2005-2709", "CVE-2005-2973", "CVE-2005-3257", "CVE-2005-3783", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4618");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1018-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1018-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1018");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-source-2.4.27' package(s) announced via the DSA-1018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The original update lacked recompiled ALSA modules against the new kernel ABI. Furthermore, kernel-latest-2.4-sparc now correctly depends on the updated packages. For completeness we're providing the original problem description:

Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2004-0887

Martin Schwidefsky discovered that the privileged instruction SACF (Set Address Space Control Fast) on the S/390 platform is not handled properly, allowing for a local user to gain root privileges.

CVE-2004-1058

A race condition allows for a local user to read the environment variables of another process that is still spawning through /proc/.../cmdline.

CVE-2004-2607

A numeric casting discrepancy in sdla_xfer allows local users to read portions of kernel memory via a large len argument which is received as an int but cast to a short, preventing read loop from filling a buffer.

CVE-2005-0449

An error in the skb_checksum_help() function from the netfilter framework has been discovered that allows the bypass of packet filter rules or a denial of service attack.

CVE-2005-1761

A vulnerability in the ptrace subsystem of the IA-64 architecture can allow local attackers to overwrite kernel memory and crash the kernel.

CVE-2005-2457

Tim Yamin discovered that insufficient input validation in the compressed ISO file system (zisofs) allows a denial of service attack through maliciously crafted ISO images.

CVE-2005-2555

Herbert Xu discovered that the setsockopt() function was not restricted to users/processes with the CAP_NET_ADMIN capability. This allows attackers to manipulate IPSEC policies or initiate a denial of service attack.

CVE-2005-2709

Al Viro discovered a race condition in the /proc handling of network devices. A (local) attacker could exploit the stale reference after interface shutdown to cause a denial of service or possibly execute code in kernel mode.

CVE-2005-2973

Tetsuo Handa discovered that the udp_v6_get_port() function from the IPv6 code can be forced into an endless loop, which allows a denial of service attack.

CVE-2005-3257

Rudolf Polzer discovered that the kernel improperly restricts access to the KDSKBSENT ioctl, which can possibly lead to privilege escalation.

CVE-2005-3783

The ptrace code using CLONE_THREAD didn't use the thread group ID to determine whether the caller is attaching to itself, which allows a denial of service attack.

CVE-2005-3806

Yen Zheng discovered that the IPv6 flow label code modified an incorrect variable, which could lead to memory corruption and denial of service.

CVE-2005-3848

Ollie Wild discovered a memory leak in the icmp_push_reply() function, which allows denial of service through memory consumption.

CVE-2005-3857

Chris ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.4.27", ver:"2.4.27-10sarge2", rls:"DEB3.1"))) {
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
