# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2534.1");
  script_cve_id("CVE-2022-3566", "CVE-2022-45884", "CVE-2022-45885", "CVE-2022-45886", "CVE-2022-45887", "CVE-2022-45919", "CVE-2023-1077", "CVE-2023-1380", "CVE-2023-2176", "CVE-2023-2194", "CVE-2023-2483", "CVE-2023-2513", "CVE-2023-28466", "CVE-2023-31084", "CVE-2023-31436", "CVE-2023-32269");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-05 17:24:37 +0000 (Fri, 05 May 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2534-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2534-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232534-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211796");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/029918.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2534-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could cause memory corruption (bsc#1208600).
- CVE-2022-3566: Fixed race condition in the TCP Handler (bsc#1204405).
- CVE-2022-45886: Fixed a .disconnect versus dvb_device_open race condition in dvb_net.c that lead to a use-after-free (bsc#1205760).
- CVE-2022-45885: Fixed a race condition in dvb_frontend.c that could cause a use-after-free when a device is disconnected (bsc#1205758).
- CVE-2022-45887: Fixed a memory leak in ttusb_dec.c caused by the lack of a dvb_frontend_detach call (bsc#1205762).
- CVE-2022-45919: Fixed a use-after-free in dvb_ca_en50221.c that could occur if there is a disconnect after an open, because of the lack of a wait_event (bsc#1205803).
- CVE-2022-45884: Fixed a use-after-free in dvbdev.c, related to dvb_register_device dynamically allocating fops (bsc#1205756).
- CVE-2023-31084: Fixed a blocking issue in drivers/media/dvb-core/dvb_frontend.c (bsc#1210783).
- CVE-2023-31436: Fixed an out-of-bounds write in qfq_change_class() because lmax can exceed QFQ_MIN_LMAX (bsc#1210940).
- CVE-2023-2194: Fixed an out-of-bounds write vulnerability in the SLIMpro I2C device driver (bsc#1210715).
- CVE-2023-32269: Fixed a use-after-free in af_netrom.c, related to the fact that accept() was also allowed for a successfully connected AF_NETROM socket (bsc#1211186).
- CVE-2023-28466: Fixed race condition that could lead to use-after-free or NULL pointer dereference in do_tls_getsockopt in net/tls/tls_main.c (bsc#1209366).
- CVE-2023-1380: Fixed a slab-out-of-bound read problem in brcmf_get_assoc_ies() (bsc#1209287).
- CVE-2023-2513: Fixed a use-after-free vulnerability in the ext4 filesystem (bsc#1211105).
- CVE-2023-2483: Fixed a use after free bug in emac_remove caused by a race condition (bsc#1211037).
- CVE-2023-2176: Fixed an out-of-boundary read in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA (bsc#1210629).

The following non-security bugs were fixed:

- ext4: add EXT4_INODE_HAS_XATTR_SPACE macro in xattr.h (bsc#1206878).
- google/gve:fix repeated words in comments (bsc#1211519).
- gve: Adding a new AdminQ command to verify driver (bsc#1211519).
- gve: Cache link_speed value from device (bsc#1211519).
- gve: Fix GFP flags when allocing pages (bsc#1211519).
- gve: Fix error return code in gve_prefill_rx_pages() (bsc#1211519).
- gve: Fix spelling mistake 'droping' -> 'dropping' (bsc#1211519).
- gve: Handle alternate miss completions (bsc#1211519).
- gve: Reduce alloc and copy costs in the GQ rx path (bsc#1211519).
- gve: Remove the code of clearing PBA bit (bsc#1211519).
- gve: Secure enough bytes in the first TX desc for all TCP pkts (bsc#1211519).
- gve: enhance no queue page list detection (bsc#1211519).
- hv: vmbus: Optimize ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150100.197.148.1", rls:"SLES15.0SP1"))) {
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
