# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56787");
  script_cve_id("CVE-2003-0984", "CVE-2004-0138", "CVE-2004-0394", "CVE-2004-0427", "CVE-2004-0447", "CVE-2004-0554", "CVE-2004-0565", "CVE-2004-0685", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-0997", "CVE-2004-1016", "CVE-2004-1017", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1074", "CVE-2004-1234", "CVE-2004-1235", "CVE-2004-1333", "CVE-2004-1335", "CVE-2005-0001", "CVE-2005-0003", "CVE-2005-0124", "CVE-2005-0135", "CVE-2005-0384", "CVE-2005-0489", "CVE-2005-0504");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1070-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-1070-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1070-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1070");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-image-sparc-2.4, kernel-patch-2.4.19-mips, kernel-source-2.4.19' package(s) announced via the DSA-1070-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2004-0427

A local denial of service vulnerability in do_fork() has been found.

CVE-2005-0489

A local denial of service vulnerability in proc memory handling has been found.

CVE-2004-0394

A buffer overflow in the panic handling code has been found.

CVE-2004-0447

A local denial of service vulnerability through a null pointer dereference in the IA64 process handling code has been found.

CVE-2004-0554

A local denial of service vulnerability through an infinite loop in the signal handler code has been found.

CVE-2004-0565

An information leak in the context switch code has been found on the IA64 architecture.

CVE-2004-0685

Unsafe use of copy_to_user in USB drivers may disclose sensitive information.

CVE-2005-0001

A race condition in the i386 page fault handler may allow privilege escalation.

CVE-2004-0883

Multiple vulnerabilities in the SMB filesystem code may allow denial of service or information disclosure.

CVE-2004-0949

An information leak discovered in the SMB filesystem code.

CVE-2004-1016

A local denial of service vulnerability has been found in the SCM layer.

CVE-2004-1333

An integer overflow in the terminal code may allow a local denial of service vulnerability.

CVE-2004-0997

A local privilege escalation in the MIPS assembly code has been found.

CVE-2004-1335

A memory leak in the ip_options_get() function may lead to denial of service.

CVE-2004-1017

Multiple overflows exist in the io_edgeport driver which might be usable as a denial of service attack vector.

CVE-2005-0124

Bryan Fulton reported a bounds checking bug in the coda_pioctl function which may allow local users to execute arbitrary code or trigger a denial of service attack.

CVE-2003-0984

Improper initialization of the RTC may disclose information.

CVE-2004-1070

Insufficient input sanitising in the load_elf_binary() function may lead to privilege escalation.

CVE-2004-1071

Incorrect error handling in the binfmt_elf loader may lead to privilege escalation.

CVE-2004-1072

A buffer overflow in the binfmt_elf loader may lead to privilege escalation or denial of service.

CVE-2004-1073

The open_exec function may disclose information.

CVE-2004-1074

The binfmt code is vulnerable to denial of service through malformed a.out binaries.

CVE-2004-0138

A denial of service vulnerability in the ELF loader has been found.

CVE-2004-1068

A programming error in the unix_dgram_recvmsg() function may lead to privilege escalation.

CVE-2004-1234

The ELF loader is vulnerable to denial of service through malformed binaries.

CVE-2005-0003

Crafted ELF binaries may lead to privilege escalation, due to insufficient checking of overlapping memory ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-image-sparc-2.4, kernel-patch-2.4.19-mips, kernel-source-2.4.19' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.4.19", ver:"2.4.19-4.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.4.19", ver:"2.4.19-0.020911.1.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.4.19-sparc", ver:"26woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.19-r4k-ip22", ver:"2.4.19-0.020911.1.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.19-r5k-ip22", ver:"2.4.19-0.020911.1.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.19-sun4u", ver:"26woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.4.19-sun4u-smp", ver:"26woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-2.4.19-mips", ver:"2.4.19-0.020911.1.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.4.19", ver:"2.4.19-4.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mips-tools", ver:"2.4.19-0.020911.1.woody5", rls:"DEB3.0"))) {
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
