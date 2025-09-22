# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3972.1");
  script_cve_id("CVE-2018-13405", "CVE-2018-9517", "CVE-2019-3874", "CVE-2019-3900", "CVE-2020-0429", "CVE-2020-12770", "CVE-2020-3702", "CVE-2021-0941", "CVE-2021-20322", "CVE-2021-22543", "CVE-2021-31916", "CVE-2021-34556", "CVE-2021-34981", "CVE-2021-3542", "CVE-2021-35477", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3656", "CVE-2021-3659", "CVE-2021-3679", "CVE-2021-3715", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-3759", "CVE-2021-3760", "CVE-2021-3764", "CVE-2021-3772", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-40490", "CVE-2021-41864", "CVE-2021-42008", "CVE-2021-42252", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2021-12-09 03:25:10 +0000 (Thu, 09 Dec 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:35 +0000 (Thu, 10 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3972-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3972-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213972-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192802");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-December/009872.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3972-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- Unprivileged BPF has been disabled by default to reduce attack surface as too many security issues have happened in the past (jsc#SLE-22573)

 You can re-enable via systemctl setting /proc/sys/kernel/unprivileged_bpf_disabled to 0. (kernel.unprivileged_bpf_disabled = 0)


The following security bugs were fixed:

- CVE-2021-0941: In bpf_skb_change_head of filter.c, there is a possible out of bounds read due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation (bnc#1192045).
- CVE-2021-31916: An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-device driver module in the Linux kernel A bound check failure allowed an attacker with special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or a leak of internal kernel information. The highest threat from this vulnerability is to system availability (bnc#1192781).
- CVE-2021-20322: Make the ipv4 and ipv6 ICMP exception caches less predictive to avoid information leaks about UDP ports in use. (bsc#1191790)
- CVE-2021-34981: Fixed file refcounting in cmtp when cmtp_attach_device fails. (bsc#1191961)
- CVE-2021-3655: Fixed a missing size validations on inbound SCTP packets, which may have allowed the kernel to read uninitialized memory (bsc#1188563).
- CVE-2021-3715: Fixed a use-after-free in route4_change() in net/sched/cls_route.c (bsc#1190349).
- CVE-2021-3760: Fixed a use-after-free vulnerability with the ndev->rf_conn_info object (bsc#1190067).
- CVE-2021-42739: The firewire subsystem had a buffer overflow related to drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt mishandled bounds checking (bsc#1184673).
- CVE-2021-3542: Fixed heap buffer overflow in firedtv driver (bsc#1186063).
- CVE-2021-42252: Fixed an issue inside aspeed_lpc_ctrl_mmap that could have allowed local attackers to access the Aspeed LPC control interface to overwrite memory in the kernel and potentially execute privileges (bnc#1190479).
- CVE-2021-41864: Fixed prealloc_elems_and_freelist that allowed unprivileged users to trigger an eBPF multiplication integer overflow with a resultant out-of-bounds write (bnc#1191317).
- CVE-2021-42008: Fixed a slab out-of-bounds write in the decode_data function in drivers/net/hamradio/6pack.c. Input from a process that had the CAP_NET_ADMIN capability could have lead to root access (bsc#1191315).
- CVE-2021-37159: Fixed use-after-free and a double free inside hso_free_net_device in drivers/net/usb/hso.c when unregister_netdev is called without checking for the NETREG_REGISTERED state (bnc#1188601).
- CVE-2020-3702: Fixed a bug which ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.83.2", rls:"SLES12.0SP4"))) {
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
