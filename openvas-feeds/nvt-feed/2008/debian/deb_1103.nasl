# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57028");
  script_cve_id("CVE-2005-3359", "CVE-2006-0038", "CVE-2006-0039", "CVE-2006-0456", "CVE-2006-0554", "CVE-2006-0555", "CVE-2006-0557", "CVE-2006-0558", "CVE-2006-0741", "CVE-2006-0742", "CVE-2006-0744", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1368", "CVE-2006-1523", "CVE-2006-1524", "CVE-2006-1525", "CVE-2006-1857", "CVE-2006-1858", "CVE-2006-1863", "CVE-2006-1864", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1103)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1103");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1103");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1103");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-source-2.6.8' package(s) announced via the DSA-1103 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-3359

Franz Filz discovered that some socket calls permit causing inconsistent reference counts on loadable modules, which allows local users to cause a denial of service.

CVE-2006-0038

'Solar Designer' discovered that arithmetic computations in netfilter's do_replace() function can lead to a buffer overflow and the execution of arbitrary code. However, the operation requires CAP_NET_ADMIN privileges, which is only an issue in virtualization systems or fine grained access control systems.

CVE-2006-0039

'Solar Designer' discovered a race condition in netfilter's do_add_counters() function, which allows information disclosure of kernel memory by exploiting a race condition. Likewise, it requires CAP_NET_ADMIN privileges.

CVE-2006-0456

David Howells discovered that the s390 assembly version of the strnlen_user() function incorrectly returns some string size values.

CVE-2006-0554

It was discovered that the ftruncate() function of XFS can expose unallocated blocks, which allows information disclosure of previously deleted files.

CVE-2006-0555

It was discovered that some NFS file operations on handles mounted with O_DIRECT can force the kernel into a crash.

CVE-2006-0557

It was discovered that the code to configure memory policies allows tricking the kernel into a crash, thus allowing denial of service.

CVE-2006-0558

It was discovered by Cliff Wickman that perfmon for the IA64 architecture allows users to trigger a BUG() assert, which allows denial of service.

CVE-2006-0741

Intel EM64T systems were discovered to be susceptible to a local DoS due to an endless recursive fault related to a bad ELF entry address.

CVE-2006-0742

Alan and Gareth discovered that the ia64 platform had an incorrectly declared die_if_kernel() function as 'does never return' which could be exploited by a local attacker resulting in a kernel crash.

CVE-2006-0744

The Linux kernel did not properly handle uncanonical return addresses on Intel EM64T CPUs, reporting exceptions in the SYSRET instead of the next instruction, causing the kernel exception handler to run on the user stack with the wrong GS. This may result in a DoS due to a local user changing the frames.

CVE-2006-1056

AMD64 machines (and other 7th and 8th generation AuthenticAMD processors) were found to be vulnerable to sensitive information leakage, due to how they handle saving and restoring the FOP, FIP, and FDP x87 registers in FXSAVE/FXRSTOR when an exception is pending. This allows a process to determine portions of the state of floating point instructions of other processes.

CVE-2006-1242

Marco Ivaldi discovered that there was an unintended information disclosure allowing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-source-2.6.8' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-16sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-16sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-16sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-16sarge3", rls:"DEB3.1"))) {
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
