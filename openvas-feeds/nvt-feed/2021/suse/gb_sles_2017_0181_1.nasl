# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0181.1");
  script_cve_id("CVE-2015-1350", "CVE-2015-8964", "CVE-2016-7039", "CVE-2016-7042", "CVE-2016-7425", "CVE-2016-7913", "CVE-2016-7917", "CVE-2016-8645", "CVE-2016-8666", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9793", "CVE-2016-9919");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-28 17:22:55 +0000 (Wed, 28 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0181-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0181-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170181-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999932");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-January/002564.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0181-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.38 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2015-1350: The VFS subsystem in the Linux kernel 3.x provides an incomplete set of requirements for setattr operations that underspecifies removing extended privilege attributes, which allowed local users to cause a denial of service (capability stripping) via a failed invocation of a system call, as demonstrated by using chown to remove a capability from the ping or Wireshark dumpcap program (bnc#914939).
- CVE-2015-8964: The tty_set_termios_ldisc function in drivers/tty/tty_ldisc.c in the Linux kernel allowed local users to obtain sensitive information from kernel memory by reading a tty data structure (bnc#1010507).
- CVE-2016-7039: The IP stack in the Linux kernel allowed remote attackers to cause a denial of service (stack consumption and panic) or possibly have unspecified other impact by triggering use of the GRO path for large crafted packets, as demonstrated by packets that contain only VLAN headers, a related issue to CVE-2016-8666 (bnc#1001486).
- CVE-2016-7042: The proc_keys_show function in security/keys/proc.c in the Linux kernel through 4.8.2, when the GNU Compiler Collection (gcc) stack protector is enabled, uses an incorrect buffer size for certain timeout data, which allowed local users to cause a denial of service (stack memory corruption and panic) by reading the /proc/keys file (bnc#1004517).
- CVE-2016-7425: The arcmsr_iop_message_xfer function in drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did not restrict a certain length field, which allowed local users to gain privileges or cause a denial of service (heap-based buffer overflow) via an ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).
- CVE-2016-7913: The xc2028_set_config function in drivers/media/tuners/tuner-xc2028.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (use-after-free) via vectors involving omission of the firmware name from a certain data structure (bnc#1010478).
- CVE-2016-7917: The nfnetlink_rcv_batch function in net/netfilter/nfnetlink.c in the Linux kernel did not check whether a batch message's length field is large enough, which allowed local users to obtain sensitive information from kernel memory or cause a denial of service (infinite loop or out-of-bounds read) by leveraging the CAP_NET_ADMIN capability (bnc#1010444).
- CVE-2016-8645: The TCP stack in the Linux kernel mishandled skb truncation, which allowed local users to cause a denial of service (system crash) via a crafted application that made sendto system calls, related to net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c (bnc#1009969).
- CVE-2016-8666: The IP stack in the Linux kernel allowed remote attackers to cause a denial of service (stack consumption and panic) or possibly have unspecified other impact by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.38~93.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.38~93.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.38~93.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.38~93.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.38~93.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.38~93.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.38~93.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.38~93.1", rls:"SLES12.0SP2"))) {
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
