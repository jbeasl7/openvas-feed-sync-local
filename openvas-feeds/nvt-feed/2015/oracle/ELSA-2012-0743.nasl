# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123900");
  script_cve_id("CVE-2012-0044", "CVE-2012-1179", "CVE-2012-2119", "CVE-2012-2121", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2373");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:02 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-29 15:27:00 +0000 (Wed, 29 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-0743)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0743");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0743.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-0743 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-220.23.1.el6]
- [net] bond: Make LRO flag follow slave settings (Neil Horman) [831176 794647]

[2.6.32-220.22.1.el6]
- [net] ipv4/netfilter: TCP and raw fix for ip_route_me_harder (Jiri Benc) [824429 812108]

[2.6.32-220.21.1.el6]
- [security] fix compile error in commoncap.c (Eric Paris) [806725 806726] {CVE-2012-2123}
- [security] fcaps: clear the same personality flags as suid when fcaps are used (Eric Paris) [806725 806726] {CVE-2012-2123}
- [net] rds: fix rds-ping inducing kernel panic (Jay Fenlason) [822757 803936] {CVE-2012-2372}
- [net] sock: validate data_len before allocating skb in sock_alloc_send_pskb() (Jason Wang) [816292 814504] {CVE-2012-2136}
- [virt] kvm: Fix buffer overflow in kvm_set_irq() (Avi Kivity) [816154 816155] {CVE-2012-2137}
- [drm] integer overflow in drm_mode_dirtyfb_ioctl() (Dave Airlie) [773249 773250] {CVE-2012-0044}
- [net] netfilter: Fix ip_route_me_harder triggering ip_rt_bug (Jiri Benc) [824429 812108]
- [net] netfilter/tproxy: do not assign timewait sockets to skb->sk (Jiri Benc) [824429 812108]
- [virt] xenpv: avoid paravirt __pmd in read_pmd_atomic (Andrew Jones) [823903 822697]
- [infiniband] mlx4: fix RoCE oops (Doug Ledford) [799946 749059]
- [mm] read_pmd_atomic: fix pmd_populate SMP race condition (Andrea Arcangeli) [822824 820762] {CVE-2012-2373}
- [infiniband] mlx4: check return code and bail on error (Doug Ledford) [799946 749059]
- [infiniband] mlx4: use locking when walking netdev list (Doug Ledford) [799946 749059]
- [mm] thp: fix pmd_bad() triggering in code paths holding mmap_sem read mode (Andrea Arcangeli) [803808 800328] {CVE-2012-1179}

[2.6.32-220.20.1.el6]
- [vhost] net: fix possible NULL pointer dereference of vq->bufs (Jason Wang) [814286 814288] {CVE-2012-2119}
- [net] macvtap: validate zerocopy vectors before building skb (Jason Wang) [814286 814288] {CVE-2012-2119}
- [net] macvtap: set SKBTX_DEV_ZEROCOPY only when skb is built successfully (Jason Wang) [814286 814288] {CVE-2012-2119}
- [net] macvtap: put zerocopy page when fail to get all requested user pages (Jason Wang) [814286 814288] {CVE-2012-2119}
- [net] macvtap: fix zerocopy offset calculation when building skb (Jason Wang) [814286 814288] {CVE-2012-2119}
- [net] bonding: remove entries for master_ip and vlan_ip and query devices instead (Andy Gospodarek) [816197 810299]
- [virt] KVM: lock slots_lock around device assignment (Alex Williamson) [814154 811653] {CVE-2012-2121}
- [virt] kvm: unmap pages from the iommu when slots are removed (Alex Williamson) [814154 811653] {CVE-2012-2121}
- [virt] xenfv: fix hangs when kdumping (Andrew Jones) [812953 811815]
- [s390x] zcrypt: Fix parameter checking for ZSECSENDCPRB ioctl (Hendrik Brueckner) [810125 808487]
- [drm] i915: suspend fbdev device around suspend/hibernate (Dave Airlie) [818503 746169]
- [fs] tmpfs: fix off-by-one in max_blocks checks (Eric Sandeen) [809399 783497]
- [net] bonding: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.23.1.el6", rls:"OracleLinux6"))) {
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
