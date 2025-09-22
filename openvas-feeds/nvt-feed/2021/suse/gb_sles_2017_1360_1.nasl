# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1360.1");
  script_cve_id("CVE-2015-1350", "CVE-2016-10044", "CVE-2016-10200", "CVE-2016-10208", "CVE-2016-2117", "CVE-2016-3070", "CVE-2016-5243", "CVE-2016-7117", "CVE-2016-9191", "CVE-2016-9588", "CVE-2016-9604", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7616", "CVE-2017-7645", "CVE-2017-8106");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-28 15:47:44 +0000 (Tue, 28 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1360-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171360-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/103470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993832");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002903.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:1360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.74 to receive various security and bugfixes.

Notable new/improved features:
- Improved support for Hyper-V
- Support for the tcp_westwood TCP scheduling algorithm

The following security bugs were fixed:

- CVE-2017-8106: The handle_invept function in arch/x86/kvm/vmx.c in the Linux kernel allowed privileged KVM guest OS users to cause a denial of service (NULL pointer dereference and host OS crash) via a single-context INVEPT instruction with a NULL EPT pointer (bsc#1035877).
- CVE-2017-6951: The keyring_search_aux function in security/keys/keyring.c in the Linux kernel allowed local users to cause a denial of service (NULL pointer dereference and OOPS) via a request_key system call for the 'dead' type. (bsc#1029850).
- CVE-2017-2647: The KEYS subsystem in the Linux kernel allowed local users to gain privileges or cause a denial of service (NULL pointer dereference and system crash) via vectors involving a NULL value for a certain match field, related to the keyring_search_iterator function in keyring.c. (bsc#1030593)
- CVE-2016-9604: This fixes handling of keyrings starting with '.' in KEYCTL_JOIN_SESSION_KEYRING, which could have allowed local users to manipulate privileged keyrings (bsc#1035576)
- CVE-2017-7616: Incorrect error handling in the set_mempolicy and mbind compat syscalls in mm/mempolicy.c in the Linux kernel allowed local users to obtain sensitive information from uninitialized stack data by triggering failure of a certain bitmap operation. (bnc#1033336).
- CVE-2017-7645: The NFSv2/NFSv3 server in the nfsd subsystem in the Linux kernel allowed remote attackers to cause a denial of service (system crash) via a long RPC reply, related to net/sunrpc/svc.c, fs/nfsd/nfs3xdr.c, and fs/nfsd/nfsxdr.c. (bsc#1034670).
- CVE-2017-7308: The packet_set_ring function in net/packet/af_packet.c in the Linux kernel did not properly validate certain block-size data, which allowed local users to cause a denial of service (overflow) or possibly have unspecified other impact via crafted system calls (bnc#1031579)
- CVE-2017-2671: The ping_unhash function in net/ipv4/ping.c in the Linux kernel was too late in obtaining a certain lock and consequently could not ensure that disconnect function calls are safe, which allowed local users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a socket system call (bnc#1031003)
- CVE-2017-7294: The vmw_surface_define_ioctl function in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not validate addition of certain levels data, which allowed local users to trigger an integer overflow and out-of-bounds write, and cause a denial of service (system hang or crash) or possibly gain privileges, via a crafted ioctl call for a /dev/dri/renderD* device (bnc#1031440)
- CVE-2017-7261: The vmw_surface_define_ioctl function in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.40.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.40.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.40.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.40.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.40.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.40.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.40.1", rls:"SLES12.0SP1"))) {
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
