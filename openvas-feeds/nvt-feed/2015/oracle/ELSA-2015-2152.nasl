# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122785");
  script_cve_id("CVE-2010-5313", "CVE-2013-7421", "CVE-2014-3647", "CVE-2014-7842", "CVE-2014-8171", "CVE-2014-9419", "CVE-2014-9644", "CVE-2015-0239", "CVE-2015-2925", "CVE-2015-3339", "CVE-2015-4170", "CVE-2015-5283", "CVE-2015-6526", "CVE-2015-7613", "CVE-2015-7837");
  script_tag(name:"creation_date", value:"2015-11-25 11:18:51 +0000 (Wed, 25 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-05 14:43:00 +0000 (Thu, 05 Oct 2017)");

  script_name("Oracle: Security Advisory (ELSA-2015-2152)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2152");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2152.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-2152 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-327.OL7]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-327]
- [mm] free compound page with correct order (Andrea Arcangeli) [1274867]
- [netdrv] revert 'ixgbe: Refactor busy poll socket code to address multiple issues' (John Greene) [1261275]
- [powerpc] dma: dma_set_coherent_mask() should not be GPL only (Gustavo Duarte) [1275976]

[3.10.0-326]
- [md] dm-cache: the CLEAN_SHUTDOWN flag was not being set (Mike Snitzer) [1274450]
- [md] dm-btree: fix leak of bufio-backed block in btree_split_beneath error path (Mike Snitzer) [1274393]
- [md] dm-btree-remove: fix a bug when rebalancing nodes after removal (Mike Snitzer) [1274396]
- [fs] nfsd: fix duplicated destroy_delegation code introduced by backport ('J. Bruce Fields') [1273228]
- [fs] xfs: validate transaction header length on log recovery (Brian Foster) [1164135]
- [net] ipv6: don't use CHECKSUM_PARTIAL on MSG_MORE/UDP_CORK sockets (Hannes Frederic Sowa) [1271759]
- [net] add length argument to skb_copy_and_csum_datagram_iovec (Sabrina Dubroca) [1269228]
- [x86] kvm: fix edge EOI and IOAPIC reconfig race (Radim Krcmar) [1271333]
- [x86] kvm: set KVM_REQ_EVENT when updating IRR (Radim Krcmar) [1271333]
- [kernel] Initialize msg/shm IPC objects before doing ipc_addid() (Lennert Buytenhek) [1271507] {CVE-2015-7613}

[3.10.0-325]
- [fs] nfsd: ensure that delegation stateid hash references are only put once ('J. Bruce Fields') [1233284]
- [fs] nfsd: ensure that the ol stateid hash reference is only put once ('J. Bruce Fields') [1233284]
- [fs] nfsv4: Fix a nograce recovery hang (Benjamin Coddington) [1264478]
- [fs] vfs: Test for and handle paths that are unreachable from their mnt_root ('Eric W. Biederman') [1209371] {CVE-2015-2925}
- [fs] dcache: Handle escaped paths in prepend_path ('Eric W. Biederman') [1209371] {CVE-2015-2925}
- [fs] xfs: add an xfs_zero_eof() tracepoint (Brian Foster) [1260383]
- [fs] xfs: always drain dio before extending aio write submission (Brian Foster) [1260383]
- [md] dm-cache: fix NULL pointer when switching from cleaner policy (Mike Snitzer) [1269959]
- [mm] Temporary fix for BUG_ON() triggered by THP vs. gup() race (David Gibson) [1268999]
- [hid] usbhid: improve handling of Clear-Halt and reset (Don Zickus) [1260123]
- [drm] qxl: fix framebuffer dirty rectangle tracking (Gerd Hoffmann) [1268293]
- [s390] hmcdrv: fix interrupt registration (Hendrik Brueckner) [1262735]
- [block] blk-mq: fix deadlock when reading cpu_list (Jeff Moyer) [1260615]
- [block] blk-mq: avoid inserting requests before establishing new mapping (Jeff Moyer) [1260615]
- [block] blk-mq: fix q->mq_usage_counter access race (Jeff Moyer) [1260615]
- [block] blk-mq: Fix use after of free q->mq_map (Jeff Moyer) [1260615]
- [block] blk-mq: fix sysfs registration/unregistration race (Jeff Moyer) [1260615]
- [block] blk-mq: avoid setting hctx->tags->cpumask before allocation (Jeff Moyer) [1260615]
- [netdrv] ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.el7", rls:"OracleLinux7"))) {
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
