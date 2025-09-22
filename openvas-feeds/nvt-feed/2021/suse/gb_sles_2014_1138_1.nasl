# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1138.1");
  script_cve_id("CVE-2013-1860", "CVE-2013-4162", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2014-0203", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943", "CVE-2014-5077");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-08-01 17:41:53 +0000 (Fri, 01 Aug 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1138-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1138-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141138-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2014:1138-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 SP1 LTSS received a roll up update to fix several security and non-security issues.

The following security issues have been fixed:

 * CVE-2013-1860: Heap-based buffer overflow in the wdm_in_callback
 function in drivers/usb/class/cdc-wdm.c in the Linux kernel before
 3.8.4 allows physically proximate attackers to cause a denial of
 service (system crash) or possibly execute arbitrary code via a
 crafted cdc-wdm USB device. (bnc#806431)
 * CVE-2013-4162: The udp_v6_push_pending_frames function in
 net/ipv6/udp.c in the IPv6 implementation in the Linux kernel
 through 3.10.3 makes an incorrect function call for pending data,
 which allows local users to cause a denial of service (BUG and
 system crash) via a crafted application that uses the UDP_CORK
 option in a setsockopt system call. (bnc#831058)
 * CVE-2014-0203: The __do_follow_link function in fs/namei.c in the
 Linux kernel before 2.6.33 does not properly handle the last
 pathname component during use of certain filesystems, which allows
 local users to cause a denial of service (incorrect free operations
 and system crash) via an open system call. (bnc#883526)
 * CVE-2014-3144: The (1) BPF_S_ANC_NLATTR and (2)
 BPF_S_ANC_NLATTR_NEST extension implementations in the sk_run_filter
 function in net/core/filter.c in the Linux kernel through 3.14.3 do
 not check whether a certain length value is sufficiently large,
 which allows local users to cause a denial of service (integer
 underflow and system crash) via crafted BPF instructions. NOTE: the
 affected code was moved to the __skb_get_nlattr and
 __skb_get_nlattr_nest functions before the vulnerability was
 announced. (bnc#877257)
 * CVE-2014-3145: The BPF_S_ANC_NLATTR_NEST extension implementation in
 the sk_run_filter function in net/core/filter.c in the Linux kernel
 through 3.14.3 uses the reverse order in a certain subtraction,
 which allows local users to cause a denial of service (over-read and
 system crash) via crafted BPF instructions. NOTE: the affected code
 was moved to the __skb_get_nlattr_nest function before the
 vulnerability was announced. (bnc#877257)
 * CVE-2014-3917: kernel/auditsc.c in the Linux kernel through 3.14.5,
 when CONFIG_AUDITSYSCALL is enabled with certain syscall rules,
 allows local users to obtain potentially sensitive single-bit values
 from kernel memory or cause a denial of service (OOPS) via a large
 value of a syscall number. (bnc#880484)
 * CVE-2014-4508: arch/x86/kernel/entry_32.S in the Linux kernel
 through 3.15.1 on 32-bit x86 platforms, when syscall auditing is
 enabled and the sep CPU feature flag is set, allows local users to
 cause a denial
 of service (OOPS and system crash) via an invalid syscall number, as demonstrated by number 1000. (bnc#883724)
 * CVE-2014-4652: Race condition in the tlv handler functionality in
 the snd_ctl_elem_user_tlv function in sound/core/control.c in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1"))) {
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
