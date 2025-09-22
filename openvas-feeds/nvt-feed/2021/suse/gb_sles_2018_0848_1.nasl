# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0848.1");
  script_cve_id("CVE-2016-7915", "CVE-2017-12190", "CVE-2017-13166", "CVE-2017-15299", "CVE-2017-16644", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18017", "CVE-2017-18204", "CVE-2017-18208", "CVE-2017-18221", "CVE-2018-1066", "CVE-2018-1068", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-6927", "CVE-2018-7566");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-17 15:05:59 +0000 (Wed, 17 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0848-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0848-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180848-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085447");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003857.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-1068: Fixed flaw in the implementation of 32-bit syscall interface
 for bridging. This allowed a privileged user to arbitrarily write to a limited
 range of kernel memory (bnc#1085107).
- CVE-2017-18221: The __munlock_pagevec function allowed local users to cause a
 denial of service (NR_MLOCK accounting corruption) via crafted use of mlockall
 and munlockall system calls (bnc#1084323).
- CVE-2018-1066: Prevent NULL pointer dereference in
 fs/cifs/cifsencrypt.c:setup_ntlmv2_rsp() that allowed an attacker controlling a
 CIFS server to kernel panic a client that has this server mounted, because an
 empty TargetInfo field in an NTLMSSP setup negotiation response was mishandled
 during session recovery (bnc#1083640).
- CVE-2017-13166: Prevent elevation of privilege vulnerability in the kernel
 v4l2 video driver (bnc#1072865).
- CVE-2017-16911: The vhci_hcd driver allowed local attackers to disclose
 kernel memory addresses. Successful exploitation required that a USB device was
 attached over IP (bnc#1078674).
- CVE-2017-15299: The KEYS subsystem mishandled use of add_key for a key that
 already exists but is uninstantiated, which allowed local users to cause a
 denial of service (NULL pointer dereference and system crash) or possibly have
 unspecified other impact via a crafted system call (bnc#1063416).
- CVE-2017-18208: The madvise_willneed function kernel allowed local users to
 cause a denial of service (infinite loop) by triggering use of MADVISE_WILLNEED
 for a DAX mapping (bnc#1083494).
- CVE-2018-7566: The ALSA sequencer core initializes the event pool on demand
 by invoking snd_seq_pool_init() when the first write happens and the pool is
 empty. A user could have reset the pool size manually via ioctl concurrently,
 which may have lead UAF or out-of-bound access (bsc#1083483).
- CVE-2017-18204: The ocfs2_setattr function allowed local users to cause a
 denial of service (deadlock) via DIO requests (bnc#1083244).
- CVE-2017-16644: The hdpvr_probe function allowed local users to cause a
 denial of service (improper error handling and system crash) or possibly have
 unspecified other impact via a crafted USB device (bnc#1067118).
- CVE-2018-6927: The futex_requeue function allowed attackers to cause a denial
 of service (integer overflow) or possibly have unspecified other impact by
 triggering a negative wake or requeue value (bnc#1080757).
- CVE-2017-16914: The 'stub_send_ret_submit()' function allowed attackers to
 cause a denial of service (NULL pointer dereference) via a specially crafted
 USB over IP packet (bnc#1078669).
- CVE-2016-7915: The hid_input_field function allowed physically proximate
 attackers to obtain sensitive information from kernel memory or cause a denial
 of service (out-of-bounds read) by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.85.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.85.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.85.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.85.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.85.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.85.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.85.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_85-default", rpm:"kgraft-patch-3_12_74-60_64_85-default~1~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_85-xen", rpm:"kgraft-patch-3_12_74-60_64_85-xen~1~2.3.1", rls:"SLES12.0SP1"))) {
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
