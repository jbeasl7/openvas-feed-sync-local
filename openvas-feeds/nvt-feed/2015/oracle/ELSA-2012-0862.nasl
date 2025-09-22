# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123879");
  script_cve_id("CVE-2011-1083", "CVE-2011-4131");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:46 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0862)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0862");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0862.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-0862 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-279.el6]
- [netdrv] mlx4: ignore old module parameters (Jay Fenlason) [830553]

[2.6.32-278.el6]
- [kernel] sysctl: silence warning about missing strategy for file-max at boot time (Jeff Layton) [803431]
- [net] sunrpc: make new tcp_max_slot_table_entries sysctl use CTL_UNNUMBERED (Jeff Layton) [803431]
- [drm] i915: set AUD_CONFIG N_value_index for DisplayPort (Dave Airlie) [747890]
- [scsi] scsi_lib: fix scsi_io_completions SG_IO error propagation (Mike Snitzer) [827163]
- [fs] nfs: Fix corrupt read data after short READ from server (Sachin Prabhu) [817738]

[2.6.32-277.el6]
- [scsi] be2iscsi: fix dma free size mismatch regression (Mike Christie) [824287]
- [scsi] libsas: check dev->gone before submitting sata i/o (David Milburn) [824025]

[2.6.32-276.el6]
- [net] ipv4/netfilter: TCP and raw fix for ip_route_me_harder (Jiri Benc) [812108]

[2.6.32-275.el6]
- [net] bridge: fix broadcast flood regression (Jesper Brouer) [817157]
- [ipc] mqueue: use correct gfp flags in msg_insert (Doug Ledford) [750260]
- [security] fix compile error in commoncap.c (Eric Paris) [806726] {CVE-2012-2123}
- [security] fcaps: clear the same personality flags as suid when fcaps are used (Eric Paris) [806726] {CVE-2012-2123}
- [fs] proc: Fix vmstat crashing with trap divide error (Larry Woodman) [820507]
- [net] rds: fix rds-ping inducing kernel panic (Jay Fenlason) [803936] {CVE-2012-2372}
- [net] sock: validate data_len before allocating skb in sock_alloc_send_pskb() (Jason Wang) [814504] {CVE-2012-2136}
- [virt] kvm: Fix buffer overflow in kvm_set_irq() (Avi Kivity) [816155] {CVE-2012-2137}

[2.6.32-274.el6]
- [net] sunrpc: fix loss of task->tk_status after rpc_delay call in xprt_alloc_slot (Jeff Layton) [822189]
- [net] sunrpc: suppress page allocation warnings in xprt_alloc_slot() (Jeff Layton) [822189]
- [net] netfilter: Fix ip_route_me_harder triggering ip_rt_bug (Jiri Benc) [812108]
- [net] netfilter/tproxy: do not assign timewait sockets to skb->sk (Jiri Benc) [812108]
- [usb] Don't fail USB3 probe on missing legacy PCI IRQ (Don Zickus) [812254]
- [usb] Fix handoff when BIOS disables host PCI device (Don Zickus) [812254]
- [usb] Remove duplicate USB 3.0 hub feature #defines (Don Zickus) [812254]
- [usb] Set hub depth after USB3 hub reset (Don Zickus) [812254]
- [usb] xhci: Fix encoding for HS bulk/control NAK rate (Don Zickus) [812254]
- [usb] Fix issue with USB 3.0 devices after system resume (Don Zickus) [812254]
- [virt] xenpv: avoid paravirt __pmd in read_pmd_atomic (Andrew Jones) [822697]

[2.6.32-273.el6]
- [s390] qeth: remove siga retry for HiperSockets devices (Hendrik Brueckner) [817090]
- [scsi] lpfc: Changed version number to 8.3.5.68.5p (Rob Evers) [821515]
- [scsi] lpfc: Fixed system crash due to not providing SCSI error-handling host reset handler (Rob Evers) [821515]
- [scsi] lpfc: Correct handling of SLI4-port XRI resource-provisioning profile change (Rob Evers) ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~279.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~279.el6", rls:"OracleLinux6"))) {
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
