# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0767.1");
  script_cve_id("CVE-2021-44879", "CVE-2021-45095", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0487", "CVE-2022-0492", "CVE-2022-0617", "CVE-2022-0644", "CVE-2022-0847", "CVE-2022-24448", "CVE-2022-24959");
  script_tag(name:"creation_date", value:"2022-03-09 04:10:18 +0000 (Wed, 09 Mar 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 19:07:20 +0000 (Thu, 10 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0767-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0767-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220767-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196612");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-March/010399.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0767-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

Transient execution side-channel attacks attacking the Branch History Buffer (BHB),
named 'Branch Target Injection' and 'Intra-Mode Branch History Injection' are now mitigated.

The following security bugs were fixed:

- CVE-2022-0001: Fixed Branch History Injection vulnerability (bsc#1191580).
- CVE-2022-0002: Fixed Intra-Mode Branch Target Injection vulnerability (bsc#1191580).
- CVE-2022-0847: Fixed a vulnerability were a local attackers could overwrite data in arbitrary (read-only) files (bsc#1196584).
- CVE-2022-0617: Fixed a null pointer dereference in UDF file system functionality. A local user could crash the system by triggering udf_file_write_iter() via a malicious UDF image. (bsc#1196079)
- CVE-2022-0644: Fixed a denial of service by a local user. A assertion failure could be triggered in kernel_read_file_from_fd() (bsc#1196155).
- CVE-2021-44879: In gc_data_segment() in fs/f2fs/gc.c, special files were not considered, which lead to a move_data_page NULL pointer dereference (bsc#1195987).
- CVE-2022-24959: Fixed a memory leak in yam_siocdevprivate() in drivers/net/hamradio/yam.c (bsc#1195897).
- CVE-2022-0487: A use-after-free vulnerability was found in rtsx_usb_ms_drv_remove() in drivers/memstick/host/rtsx_usb_ms.c (bsc#1194516).
- CVE-2022-0492: Fixed a privilege escalation related to cgroups v1 release_agent feature, which allowed bypassing namespace isolation unexpectedly (bsc#1195543).
- CVE-2022-24448: Fixed an issue in fs/nfs/dir.c. If an application sets the O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a regular file is found, ENOTDIR should have occurred, but the server instead returned uninitialized data in the file descriptor (bsc#1195612).
- CVE-2021-45095: Fixed refcount leak in pep_sock_accept in net/phonet/pep.c (bsc#1193867).

The following non-security bugs were fixed:

- Bluetooth: bfusb: fix division by zero in send path (git-fixes).
- Bluetooth: fix the erroneous flush_work() order (git-fixes).
- EDAC/xgene: Fix deferred probing (bsc#1114648).
- IB/rdmavt: Validate remote_addr during loopback atomic tests (bsc#1114685).
- NFSv4.x: by default serialize open/close operations (bsc#1114893 bsc#1195934). Make this work-around optional
- NFSv42: Do not fail clone() unless the OP_CLONE operation failed (git-fixes).
- NFSv42: Fix pagecache invalidation after COPY/CLONE (git-fixes).
- NFSv4: Handle case where the lookup of a directory fails (git-fixes).
- NFSv4: nfs_atomic_open() can race when looking up a non-regular file (git-fixes).
- PCI: Add function 1 DMA alias quirk for Marvell 88SE9125 SATA controller (git-fixes).
- RDMA/bnxt_re: Fix query SRQ failure (bsc#1050244).
- RDMA/mlx5: Set user priority for DCT (bsc#1103991).
- RDMA/netlink: Add __maybe_unused to static inline in C file ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.113.1", rls:"SLES12.0SP5"))) {
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
