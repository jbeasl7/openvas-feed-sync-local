# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2912.1");
  script_cve_id("CVE-2015-8956", "CVE-2016-5696", "CVE-2016-6130", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7425", "CVE-2016-8658", "CVE-2016-8666");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-17 22:48:29 +0000 (Mon, 17 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2912-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162912-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/744692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/772786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999932");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002422.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2912-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.67 to receive various security and bugfixes.

The following security bugs were fixed:
- CVE-2016-7042: The proc_keys_show function in security/keys/proc.c in
 the Linux kernel used an incorrect buffer size for certain timeout data,
 which allowed local users to cause a denial of service (stack memory
 corruption and panic) by reading the /proc/keys file (bsc#1004517).
- CVE-2016-7097: The filesystem implementation in the Linux kernel
 preserved the setgid bit during a setxattr call, which allowed local
 users to gain group privileges by leveraging the existence of a setgid
 program with restrictions on execute permissions (bsc#995968).
- CVE-2015-8956: The rfcomm_sock_bind function in
 net/bluetooth/rfcomm/sock.c in the Linux kernel allowed local users to
 obtain sensitive information or cause a denial of service (NULL pointer
 dereference) via vectors involving a bind system call on a Bluetooth
 RFCOMM socket (bnc#1003925).
- CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel did not properly
 determine the rate of challenge ACK segments, which made it easier for
 man-in-the-middle attackers to hijack TCP sessions via a blind in-window
 attack (bnc#989152).
- CVE-2016-6130: Race condition in the sclp_ctl_ioctl_sccb function in
 drivers/s390/char/sclp_ctl.c in the Linux kernel allowed local users to
 obtain sensitive information from kernel memory by changing a certain
 length value, aka a 'double fetch' vulnerability (bnc#987542).
- CVE-2016-6327: drivers/infiniband/ulp/srpt/ib_srpt.c in the Linux
 kernel allowed local users to cause a denial of service (NULL pointer
 dereference and system crash) by using an ABORT_TASK command to abort
 a device write operation (bnc#994748).
- CVE-2016-6480: Race condition in the ioctl_send_fib function in
 drivers/scsi/aacraid/commctrl.c in the Linux kernel allowed local users
 to cause a denial of service (out-of-bounds access or system crash)
 by changing a certain size value, aka a 'double fetch' vulnerability
 (bnc#991608).
- CVE-2016-6828: The tcp_check_send_head function in include/net/tcp.h
 in the Linux kernel did not properly maintain certain SACK state after a
 failed data copy, which allowed local users to cause a denial of service
 (tcp_xmit_retransmit_queue use-after-free and system crash) via a crafted
 SACK option (bnc#994296).
- CVE-2016-7425: The arcmsr_iop_message_xfer function in
 drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did not restrict
 a certain length field, which allowed local users to gain privileges
 or cause a denial of service (heap-based buffer overflow) via an
 ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).
- CVE-2016-8658: Stack-based buffer overflow
 in the brcmf_cfg80211_start_ap function in
 drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux
 kernel allowed local users to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.67~60.64.18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.67~60.64.18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.67~60.64.18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.67~60.64.18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.67~60.64.18.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.67~60.64.18.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.67~60.64.18.1", rls:"SLES12.0SP1"))) {
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
