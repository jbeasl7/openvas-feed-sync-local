# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123440");
  script_cve_id("CVE-2013-1860", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0101");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-0328)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0328");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0328.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-0328 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-431.11.2]
- [net] sctp: fix sctp_sf_do_5_1D_ce to verify if peer is AUTH capable (Daniel Borkmann) [1070715 1067451] {CVE-2014-0101}
- [vhost] validate vhost_get_vq_desc return value (Michael S. Tsirkin) [1062579 1058677] {CVE-2014-0055}

[2.6.32-431.11.1]
- [net] netpoll: take rcu_read_lock_bh() in netpoll_send_skb_on_dev() (Florian Westphal) [1063271 1049052]
- [fs] cifs: sanity check length of data to send before sending (Sachin Prabhu) [1065668 1062590] {CVE-2014-0069}
- [fs] cifs: ensure that uncached writes handle unmapped areas correctly (Sachin Prabhu) [1065668 1062590] {CVE-2014-0069}
- [infiniband] ipoib: Report operstate consistently when brought up without a link (Michal Schmidt) [1064464 995300]
- [security] selinux: fix broken peer recv check (Paul Moore) [1059991 1043051]
- [fs] GFS2: Fix slab memory leak in gfs2_bufdata (Robert S Peterson) [1064913 1024024]
- [fs] GFS2: Fix use-after-free race when calling gfs2_remove_from_ail (Robert S Peterson) [1064913 1024024]
- [fs] nfs: always make sure page is up-to-date before extending a write to cover the entire page (Scott Mayhew) [1066942 1054493]
- [fs] xfs: ensure we capture IO errors correctly (Lachlan McIlroy) [1058418 1021325]
- [mm] get rid of unnecessary pageblock scanning in setup_zone_migrate_reserve (Motohiro Kosaki) [1062113 1043353]
- [security] selinux: process labeled IPsec TCP SYN-ACK packets properly in selinux_ip_postroute() (Paul Moore) [1055364 1024631]
- [security] selinux: look for IPsec labels on both inbound and outbound packets (Paul Moore) [1055364 1024631]
- [security] selinux: handle TCP SYN-ACK packets correctly in selinux_ip_postroute() (Paul Moore) [1055364 1024631]
- [security] selinux: handle TCP SYN-ACK packets correctly in selinux_ip_output() (Paul Moore) [1055364 1024631]
- [edac] e752x_edac: Fix pci_dev usage count (Aristeu Rozanski) [1058420 1029530]
- [s390] mm: handle asce-type exceptions as normal page fault (Hendrik Brueckner) [1057164 1034268]
- [s390] mm: correct tlb flush on page table upgrade (Hendrik Brueckner) [1057165 1034269]
- [net] fix memory information leaks in recv protocol handlers (Florian Westphal) [1039868 1039869]
- [usb] cdc-wdm: fix buffer overflow (Alexander Gordeev) [922000 922001] {CVE-2013-1860}
- [usb] cdc-wdm: Fix race between autosuspend and reading from the device (Alexander Gordeev) [922000 922001] {CVE-2013-1860}

[2.6.32-431.10.1]
- [fs] xfs: xfs_remove deadlocks due to inverted AGF vs AGI lock ordering (Brian Foster) [1067775 1059334]
- [x86] apic: Map the local apic when parsing the MP table (Prarit Bhargava) [1063507 1061873]

[2.6.32-431.9.1]
- [netdrv] bonding: add NETIF_F_NO_CSUM vlan_features (Ivan Vecera) [1063199 1059777]

[2.6.32-431.8.1]
- [netdrv] enic: remove enic->vlan_group check (Stefan Assmann) [1064115 1057704]

[2.6.32-431.7.1]
- [char] n_tty: Fix unsafe update of available buffer space (Jiri Benc) [1060491 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.11.2.el6", rls:"OracleLinux6"))) {
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
