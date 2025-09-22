# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1210.1");
  script_cve_id("CVE-2020-0433", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-27170", "CVE-2020-27171", "CVE-2020-27815", "CVE-2020-29368", "CVE-2020-29374", "CVE-2020-35519", "CVE-2020-36311", "CVE-2021-20219", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932", "CVE-2021-27363", "CVE-2021-27364", "CVE-2021-27365", "CVE-2021-28038", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-28972", "CVE-2021-29154", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29647", "CVE-2021-30002", "CVE-2021-3428", "CVE-2021-3444", "CVE-2021-3483");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-12 03:54:00 +0000 (Mon, 12 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1210-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1210-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211210-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184583");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2021-April/018572.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1210-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2021-3444: Fixed an issue with the bpf verifier which did not properly handle mod32 destination register truncation when the source register was known to be 0 leading to out of bounds read (bsc#1184170).
- CVE-2021-3428: Fixed an integer overflow in ext4_es_cache_extent (bsc#1173485).
- CVE-2021-29647: Fixed an issue in qrtr_recvmsg which could have allowed attackers to obtain sensitive information from kernel memory because of a partially uninitialized data structure (bsc#1184192 ).
- CVE-2021-29265: Fixed an issue in usbip_sockfd_store which could have allowed attackers to cause a denial of service due to race conditions during an update of the local and shared status (bsc#1184167).
- CVE-2021-29264: Fixed an issue in the Freescale Gianfar Ethernet driver which could have allowed attackers to cause a system crash due to a calculation of negative fragment size (bsc#1184168).
- CVE-2021-28972: Fixed a user-tolerable buffer overflow when writing a new device name to the driver from userspace, allowing userspace to write data to the kernel stack frame directly (bsc#1184198).
- CVE-2021-28971: Fixed an issue in intel_pmu_drain_pebs_nhm which could have caused a system crash because the PEBS status in a PEBS record was mishandled (bsc#1184196 ).
- CVE-2021-28964: Fixed a race condition in get_old_root which could have allowed attackers to cause a denial of service (bsc#1184193).
- CVE-2021-28688: Fixed an issue introduced by XSA-365 (bsc#1183646).
- CVE-2021-28660: Fixed an out of bounds write in rtw_wx_set_scan (bsc#1183593 ).
- CVE-2021-28038: Fixed an issue with the netback driver which was lacking necessary treatment of errors such as failed memory allocations (bsc#1183022).
- CVE-2021-27365: Fixed an issue where an unprivileged user can send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a Netlink message (bsc#1182715).
- CVE-2021-27364: Fixed an issue where an attacker could craft Netlink messages (bsc#1182717).
- CVE-2021-27363: Fixed a kernel pointer leak which could have been used to determine the address of the iscsi_transport structure (bsc#1182716).
- CVE-2021-26932: Fixed improper error handling issues in Linux grant mapping (XSA-361 bsc#1181747).
- CVE-2021-26931: Fixed an issue where Linux kernel was treating grant mapping errors as bugs (XSA-362 bsc#1181753).
- CVE-2021-26930: Fixed an improper error handling in blkback's grant mapping (XSA-365 bsc#1181843).
- CVE-2020-35519: Fixed an out-of-bounds memory access was found in x25_bind (bsc#1183696).
- CVE-2020-29368,CVE-2020-29374: Fixed an issue in copy-on-write implementation which could have granted unintended write access (bsc#1179660, bsc#1179428).
- CVE-2020-27815: Fixed an issue in JFS filesystem where could have ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.66.2", rls:"SLES12.0SP5"))) {
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
