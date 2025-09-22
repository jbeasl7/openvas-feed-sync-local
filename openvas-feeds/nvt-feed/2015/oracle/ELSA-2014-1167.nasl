# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123317");
  script_cve_id("CVE-2014-0205", "CVE-2014-3535", "CVE-2014-3917", "CVE-2014-4667");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:11 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-1167)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1167");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1167.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-1167 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-431.29.2]
- [kernel] futex: Fix errors in nested key ref-counting (Denys Vlasenko) [1094457 1094458] {CVE-2014-0205}
- [net] vxlan: fix NULL pointer dereference (Jiri Benc) [1114549 1096351] {CVE-2014-3535}

[2.6.32-431.29.1]
- [mm] hugetlb: ensure hugepage access is denied if hugepages are not supported (Gustavo Duarte) [1118782 1086450]
- [security] keys: Increase root_maxkeys and root_maxbytes sizes (Steve Dickson) [1115542 1113607]
- [fs] lockd: Ensure that nlmclnt_block resets block->b_status after a server reboot (Steve Dickson) [1110180 959006]
- [net] filter: add vlan tag access (Jiri Benc) [1108526 1082097]
- [net] filter: add XOR operation (Jiri Benc) [1108526 1082097]
- [net] filter: add SKF_AD_RXHASH and SKF_AD_CPU (Jiri Benc) [1108526 1082097]
- [net] filter: Socket filter ancillary data access for skb->dev->type (Jiri Benc) [1108526 1082097]
- [net] filter: Add SKF_AD_QUEUE instruction (Jiri Benc) [1108526 1082097]
- [net] filter: ingress socket filter by mark (Jiri Benc) [1108526 1082097]
- [netdrv] bonding: look for bridge IPs in arp monitoring (Veaceslav Falico) [1102794 704190]
- [s390] af_iucv: wrong mapping of sent and confirmed skbs (Hendrik Brueckner) [1112390 1102248]
- [s390] af_iucv: recvmsg problem for SOCK_STREAM sockets (Hendrik Brueckner) [1112390 1102248]
- [s390] af_iucv: fix recvmsg by replacing skb_pull() function (Hendrik Brueckner) [1112390 1102248]
- [s390] kernel: avoid page table walk on user space access (Hendrik Brueckner) [1111194 1099146]
- [s390] qeth: postpone freeing of qdio memory (Hendrik Brueckner) [1112134 1094379]
- [s390] qeth: Fix retry logic in hardsetup (Hendrik Brueckner) [1112134 1094379]
- [s390] qeth: Recognize return codes of ccw_device_set_online (Hendrik Brueckner) [1112134 1094379]
- [s390] qdio: remove API wrappers (Hendrik Brueckner) [1112134 1094379]
- [scsi] Ensure medium access timeout counter resets (David Jeffery) [1117153 1036884]
- [scsi] Fix error handling when no ULD is attached (David Jeffery) [1117153 1036884]
- [scsi] Handle disk devices which can not process medium access commands (David Jeffery) [1117153 1036884]
- [fs] nfs: Fix calls to drop_nlink() (Steve Dickson) [1099607 1093819]
- [mm] swap: do not skip lowest_bit in scan_swap_map() scan loop (Rafael Aquini) [1099728 1060886]
- [mm] swap: fix shmem swapping when more than 8 areas (Rafael Aquini) [1099728 1060886]
- [mm] swap: fix swapon size off-by-one (Rafael Aquini) [1099728 1060886]
- [md] avoid deadlock when dirty buffers during md_stop (Jes Sorensen) [1121541 994724]
- [x86] hyperv: bypass the timer_irq_works() check (Jason Wang) [1112226 1040349]

[2.6.32-431.28.1]
- [kernel] auditsc: audit_krule mask accesses need bounds checking (Denys Vlasenko) [1102704 1102705] {CVE-2014-3917}
- [net] ipv4: fix route cache rebuilds (Jiri Pirko) [1113824 1111631]
- [fs] nfsd: notify_change needs elevated write count (Mateusz Guzik) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.29.2.el6", rls:"OracleLinux6"))) {
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
