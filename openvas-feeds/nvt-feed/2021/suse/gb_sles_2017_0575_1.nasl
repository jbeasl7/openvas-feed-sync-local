# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0575.1");
  script_cve_id("CVE-2015-8709", "CVE-2016-7117", "CVE-2016-9806", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-5577", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-28 15:47:44 +0000 (Tue, 28 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0575-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0575-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170575-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998106");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002668.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0575-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.49 to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2016-7117: Use-after-free vulnerability in the __sys_recvmmsg function in
 net/socket.c in the Linux kernel allowed remote attackers to execute arbitrary
 code via vectors involving a recvmmsg system call that was mishandled during
 error processing (bnc#1003077).
- CVE-2017-5576: Integer overflow in the vc4_get_bcl function in
 drivers/gpu/drm/vc4/vc4_gem.c in the VideoCore DRM driver in the Linux kernel
 allowed local users to cause a denial of service or possibly have unspecified
 other impact via a crafted size value in a VC4_SUBMIT_CL ioctl call
 (bnc#1021294).
- CVE-2017-5577: The vc4_get_bcl function in drivers/gpu/drm/vc4/vc4_gem.c in
 the VideoCore DRM driver in the Linux kernel did not set an errno value upon
 certain overflow detections, which allowed local users to cause a denial of
 service (incorrect pointer dereference and OOPS) via inconsistent size values
 in a VC4_SUBMIT_CL ioctl call (bnc#1021294).
- CVE-2017-5551: The simple_set_acl function in fs/posix_acl.c in the Linux
 kernel preserved the setgid bit during a setxattr call involving a tmpfs
 filesystem, which allowed local users to gain group privileges by leveraging
 the existence of a setgid program with restrictions on execute permissions.
 (bnc#1021258).
- CVE-2017-2583: The load_segment_descriptor implementation in
 arch/x86/kvm/emulate.c in the Linux kernel improperly emulated a 'MOV SS,
 NULL selector' instruction, which allowed guest OS users to cause a denial of
 service (guest OS crash) or gain guest OS privileges via a crafted
 application (bnc#1020602).
- CVE-2017-2584: arch/x86/kvm/emulate.c in the Linux kernel allowed local users
 to obtain sensitive information from kernel memory or cause a denial of
 service (use-after-free) via a crafted application that leverages instruction
 emulation for fxrstor, fxsave, sgdt, and sidt (bnc#1019851).
- CVE-2015-8709: kernel/ptrace.c in the Linux kernel mishandled uid and gid
 mappings, which allowed local users to gain privileges by establishing a user
 namespace, waiting for a root process to enter that namespace with an unsafe
 uid or gid, and then using the ptrace system call. NOTE: the vendor states
 'there is no kernel bug here' (bnc#1010933).
- CVE-2016-9806: Race condition in the netlink_dump function in
 net/netlink/af_netlink.c in the Linux kernel allowed local users to cause a
 denial of service (double free) or possibly have unspecified other impact via
 a crafted application that made sendmsg system calls, leading to a free
 operation associated with a new dump that started earlier than anticipated
 (bnc#1013540).
- CVE-2017-5897: fixed a bug in the Linux kernel IPv6 implementation which
 allowed remote attackers to trigger an out-of-bounds access, leading to a
 denial-of-service ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.49~92.11.1", rls:"SLES12.0SP2"))) {
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
