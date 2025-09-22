# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1478.1");
  script_cve_id("CVE-2014-8086", "CVE-2014-8159", "CVE-2014-9683", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1421", "CVE-2015-1805", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3636", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-03-16 14:19:01 +0000 (Mon, 16 Mar 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1478-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1478-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151478-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/798406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940398");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-September/001563.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:1478-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 SP2 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
- CVE-2015-5707: An integer overflow in the SCSI generic driver could
 be potentially used by local attackers to crash the kernel or execute
 code.
- CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux kernel did
 not prevent the TS_COMPAT flag from reaching a user-mode task, which
 might have allowed local users to bypass the seccomp or audit protection
 mechanism via a crafted application that uses the (1) fork or (2) close
 system call, as demonstrated by an attack against seccomp before 3.16
 (bnc#926240).
- CVE-2015-0777: drivers/xen/usbback/usbback.c in the Linux kernel
 allowed guest OS users to obtain sensitive information from uninitialized
 locations in host OS kernel memory via unspecified vectors (bnc#917830).
- CVE-2015-2150: Xen and the Linux kernel did not properly restrict access
 to PCI command registers, which might have allowed local guest users to
 cause a denial of service (non-maskable interrupt and host crash) by
 disabling the (1) memory or (2) I/O decoding for a PCI Express device
 and then accessing the device, which triggers an Unsupported Request
 (UR) response (bnc#919463).
- CVE-2015-5364: A remote denial of service (hang) via UDP flood with
 incorrect package checksums was fixed. (bsc#936831).
- CVE-2015-5366: A remote denial of service (unexpected error returns)
 via UDP flood with incorrect package checksums was fixed. (bsc#936831).
- CVE-2015-1420: CVE-2015-1420: Race condition in the handle_to_path
 function in fs/fhandle.c in the Linux kernel allowed local users to bypass
 intended size restrictions and trigger read operations on additional
 memory locations by changing the handle_bytes value of a file handle
 during the execution of this function (bnc#915517).
- CVE-2015-4700: A local user could have created a bad instruction in
 the JIT processed BPF code, leading to a kernel crash (bnc#935705).
- CVE-2015-1805: The (1) pipe_read and (2) pipe_write implementations in
 fs/pipe.c in the Linux kernel did not properly consider the side effects
 of failed __copy_to_user_inatomic and __copy_from_user_inatomic calls,
 which allowed local users to cause a denial of service (system crash)
 or possibly gain privileges via a crafted application, aka an 'I/O vector
 array overrun' (bnc#933429).
- CVE-2015-3331: The __driver_rfc4106_decrypt function in
 arch/x86/crypto/aesni-intel_glue.c in the Linux kernel did not properly
 determine the memory locations used for encrypted data, which allowed
 context-dependent attackers to cause a denial of service (buffer overflow
 and system crash) or possibly execute arbitrary code by triggering a
 crypto API call, as demonstrated by use of a libkcapi test program with
 an AF_ALG(aead) socket (bnc#927257).
- CVE-2015-2922: The ndisc_router_discovery function in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.7.37.1", rls:"SLES11.0SP2"))) {
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
