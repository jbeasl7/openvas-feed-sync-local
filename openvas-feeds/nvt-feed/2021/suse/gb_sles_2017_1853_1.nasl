# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1853.1");
  script_cve_id("CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-7346", "CVE-2017-7487", "CVE-2017-7616", "CVE-2017-7618", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9150", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-31 17:33:40 +0000 (Wed, 31 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1853-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1853-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171853-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1041810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995542");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-July/003028.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:1853-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.74 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-1000365: The Linux Kernel imposes a size restriction on the arguments and environmental strings passed through RLIMIT_STACK/RLIM_INFINITY (1/4 of the size), but did not take the argument and environment pointers into account, which allowed attackers to bypass this limitation. (bnc#1039354).
- CVE-2017-1000380: sound/core/timer.c in the Linux kernel is vulnerable to a data race in the ALSA /dev/snd/timer driver resulting in local users being able to read information belonging to other users, i.e., uninitialized memory contents may be disclosed when a read and an ioctl happen at the same time (bnc#1044125).
- CVE-2017-7346: The vmw_gb_surface_define_ioctl function in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not validate certain levels data, which allowed local users to cause a denial of service (system hang) via a crafted ioctl call for a /dev/dri/renderD* device (bnc#1031796).
- CVE-2017-9242: The __ip6_append_data function in net/ipv6/ip6_output.c in the Linux kernel is too late in checking whether an overwrite of an skb data structure may occur, which allowed local users to cause a denial of service (system crash) via crafted system calls (bnc#1041431).
- CVE-2017-9076: The dccp_v6_request_recv_sock function in net/dccp/ipv6.c in the Linux kernel mishandled inheritance, which allowed local users to cause a denial of service or possibly have unspecified other impact via crafted system calls, a related issue to CVE-2017-8890 (bnc#1039885).
- CVE-2017-9077: The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c in the Linux kernel mishandled inheritance, which allowed local users to cause a denial of service or possibly have unspecified other impact via crafted system calls, a related issue to CVE-2017-8890 (bnc#1040069).
- CVE-2017-9075: The sctp_v6_create_accept_sk function in net/sctp/ipv6.c in the Linux kernel mishandled inheritance, which allowed local users to cause a denial of service or possibly have unspecified other impact via crafted system calls, a related issue to CVE-2017-8890 (bnc#1039883).
- CVE-2017-9074: The IPv6 fragmentation implementation in the Linux kernel did not consider that the nexthdr field may be associated with an invalid option, which allowed local users to cause a denial of service (out-of-bounds read and BUG) or possibly have unspecified other impact via crafted socket and send system calls (bnc#1039882).
- CVE-2017-8924: The edge_bulk_in_callback function in drivers/usb/serial/io_ti.c in the Linux kernel allowed local users to obtain sensitive information (in the dmesg ringbuffer and syslog) from uninitialized kernel memory by using a crafted USB device (posing as an io_ti USB serial device) to trigger an integer underflow. (bsc#1038982)
- CVE-2017-8925: The ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.74~92.29.1", rls:"SLES12.0SP2"))) {
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
