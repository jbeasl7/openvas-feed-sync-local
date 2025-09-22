# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1611.1");
  script_cve_id("CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1805", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-4167", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1611-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1611-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151611-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942350");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-September/001598.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:1611-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 kernel was updated to receive various security and bugfixes.

Following security bugs were fixed:

- CVE-2015-5707: An integer overflow in the SCSI generic driver could
 be potentially used by local attackers to crash the kernel or execute
 code (bsc#940338).
- CVE-2015-5364: A remote denial of service (hang) via UDP flood with
 incorrect package checksums was fixed. (bsc#936831).
- CVE-2015-5366: A remote denial of service (unexpected error returns)
 via UDP flood with incorrect package checksums was fixed. (bsc#936831).
- CVE-2015-1420: A race condition in the handle_to_path function in
 fs/fhandle.c in the Linux kernel allowed local users to bypass intended
 size restrictions and trigger read operations on additional memory
 locations by changing the handle_bytes value of a file handle during
 the execution of this function (bnc#915517).
- CVE-2015-4700: A local user could have created a bad instruction in
 the JIT processed BPF code, leading to a kernel crash (bnc#935705).
- CVE-2015-4167: The UDF filesystem in the Linux kernel was vulnerable
 to a crash which could occur while fetching inode information from a
 corrupted/malicious udf file system image. (bsc#933907).
- CVE-2014-9728 CVE-2014-9729 CVE-2014-9730 CVE-2014-9731: Various
 issues in handling UDF filesystems in the Linux kernel allowed the
 corruption of kernel memory and other issues. An attacker able to mount
 a corrupted/malicious UDF file system image could cause the kernel to
 crash. (bsc#933904 bsc#933896)
- CVE-2015-2150: The Linux kernel did not properly restrict access to
 PCI command registers, which might have allowed local guest users to
 cause a denial of service (non-maskable interrupt and host crash) by
 disabling the (1) memory or (2) I/O decoding for a PCI Express device
 and then accessing the device, which triggers an Unsupported Request
 (UR) response (bsc#919463).
- CVE-2015-0777: drivers/xen/usbback/usbback.c as used in the Linux
 kernel 2.6.x and 3.x in SUSE Linux distributions, allowed guest OS users
 to obtain sensitive information from uninitialized locations in host OS
 kernel memory via unspecified vectors (bnc#917830).
- CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux kernel did
 not prevent the TS_COMPAT flag from reaching a user-mode task, which
 might have allowed local users to bypass the seccomp or audit protection
 mechanism via a crafted application that uses the (1) fork or (2) close
 system call, as demonstrated by an attack against seccomp before 3.16
 (bnc#926240).
- CVE-2015-1805: The Linux kernels implementation of vectored pipe
 read and write functionality did not take into account the I/O vectors
 that were already processed when retrying after a failed atomic access
 operation, potentially resulting in memory corruption due to an I/O vector
 array overrun. A local, unprivileged user could use this flaw to crash
 the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-extra", rpm:"kernel-bigsmp-extra~3.0.101~0.47.67.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~0.47.67.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~0.47.67.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~0.47.67.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~0.47.67.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.67.2", rls:"SLES11.0SP3"))) {
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
