# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3935.1");
  script_cve_id("CVE-2017-17862", "CVE-2017-17864", "CVE-2018-13405", "CVE-2018-16882", "CVE-2020-0429", "CVE-2020-12655", "CVE-2020-14305", "CVE-2020-3702", "CVE-2020-4788", "CVE-2021-20265", "CVE-2021-20322", "CVE-2021-31916", "CVE-2021-33033", "CVE-2021-34556", "CVE-2021-34981", "CVE-2021-3542", "CVE-2021-35477", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3659", "CVE-2021-3679", "CVE-2021-3715", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3752", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-3760", "CVE-2021-3772", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-3896", "CVE-2021-40490", "CVE-2021-42008", "CVE-2021-42739", "CVE-2021-43389");
  script_tag(name:"creation_date", value:"2021-12-07 08:23:32 +0000 (Tue, 07 Dec 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-08 16:13:13 +0000 (Fri, 08 Oct 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3935-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3935-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213935-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192781");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-December/009856.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3935-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- Unprivileged BPF has been disabled by default to reduce attack surface as too many security issues have happened in the past (jsc#SLE-22573)

 You can re-enable via systemctl setting /proc/sys/kernel/unprivileged_bpf_disabled to 0. (kernel.unprivileged_bpf_disabled = 0)

- CVE-2021-31916: An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-device driver module in the Linux kernel A bound check failure allowed an attacker with special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or a leak of internal kernel information. The highest threat from this vulnerability is to system availability (bnc#1192781).
- CVE-2021-20322: Make the ipv4 and ipv6 ICMP exception caches less predictive to avoid information leaks about UDP ports in use. (bsc#1191790)
- CVE-2021-34981: Fixed file refcounting in cmtp when cmtp_attach_device fails (bsc#1191961).
- CVE-2020-12655: An issue was discovered in xfs_agf_verify in fs/xfs/libxfs/xfs_alloc.c. Attackers may trigger a sync of excessive duration via an XFS v5 image with crafted metadata, aka CID-d0c7feaf8767 (bnc#1171217).
- CVE-2021-43389: There was an array-index-out-of-bounds flaw in the detach_capi_ctr function in drivers/isdn/capi/kcapi.c (bnc#1191958).
- CVE-2021-37159: hso_free_net_device in drivers/net/usb/hso.c called unregister_netdev without checking for the NETREG_REGISTERED state, leading to a use-after-free and a double free (bnc#1188601).
- CVE-2021-34556: An unprivileged BPF program can obtain sensitive information from kernel memory via a Speculative Store Bypass side-channel attack because the protection mechanism neglects the possibility of uninitialized memory locations on the BPF stack (bnc#1188983).
- CVE-2021-35477: An unprivileged BPF program can obtain sensitive information from kernel memory via a Speculative Store Bypass side-channel attack because a certain preempting store operation did not necessarily occur before a store operation that has an attacker-controlled value (bnc#1188985).
- CVE-2017-17862: kernel/bpf/verifier.c in the Linux kernel ignores unreachable code, even though it would still be processed by JIT compilers. This behavior, also considered an improper branch-pruning logic issue, could possibly be used by local users for denial of service (bnc#1073928).
- CVE-2017-17864: kernel/bpf/verifier.c in the Linux kernel mishandled states_equal comparisons between the pointer data type and the UNKNOWN_VALUE data type, which allowed local users to obtain potentially sensitive address information, aka a 'pointer leak (bnc#1073928).
- CVE-2021-20265: A flaw was found in the way memory resources were freed in the unix_stream_recvmsg function in the Linux kernel when a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-kgraft", rpm:"kernel-default-kgraft~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.150.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_150-default", rpm:"kgraft-patch-4_4_180-94_150-default~1~4.3.1", rls:"SLES12.0SP3"))) {
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
