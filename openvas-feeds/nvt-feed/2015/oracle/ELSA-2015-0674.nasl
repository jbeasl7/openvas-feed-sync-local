# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123170");
  script_cve_id("CVE-2014-7822", "CVE-2014-8159", "CVE-2014-8160", "CVE-2014-8369");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 19:37:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2015-0674)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0674");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0674.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-0674 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-504.12.2]
- [infiniband] core: Prevent integer overflow in ib_umem_get address arithmetic (Doug Ledford) [1181173 1179327] {CVE-2014-8159}

[2.6.32-504.12.1]
- [fs] splice: perform generic write checks (Eric Sandeen) [1163798 1155900] {CVE-2014-7822}

[2.6.32-504.11.1]
- [virt] kvm: excessive pages un-pinning in kvm_iommu_map error path (Jacob Tanenbaum) [1156520 1156521] {CVE-2014-8369}
- [x86] crypto: Add support for 192 & 256 bit keys to AESNI RFC4106 (Jarod Wilson) [1184332 1176211]
- [block] nvme: Clear QUEUE_FLAG_STACKABLE (David Milburn) [1180555 1155715]
- [net] netfilter: conntrack: disable generic tracking for known protocols (Daniel Borkmann) [1182071 1114697] {CVE-2014-8160}
- [xen] pvhvm: Fix vcpu hotplugging hanging (Vitaly Kuznetsov) [1179343 1164278]
- [xen] pvhvm: Don't point per_cpu(xen_vpcu, 33 and larger) to shared_info (Vitaly Kuznetsov) [1179343 1164278]
- [xen] enable PVHVM VCPU placement when using more than 32 CPUs (Vitaly Kuznetsov) [1179343 1164278]
- [xen] support large numbers of CPUs with vcpu info placement (Vitaly Kuznetsov) [1179343 1164278]

[2.6.32-504.10.1]
- [netdrv] tg3: Change nvram command timeout value to 50ms (Ivan Vecera) [1182903 1176230]

[2.6.32-504.9.1]
- [net] ipv6: increase ip6_rt_max_size to 16384 (Hannes Frederic Sowa) [1177581 1112946]
- [net] ipv6: don't set DST_NOCOUNT for remotely added routes (Hannes Frederic Sowa) [1177581 1112946]
- [net] ipv6: don't count addrconf generated routes against gc limit (Hannes Frederic Sowa) [1177581 1112946]
- [net] ipv6: Don't put artificial limit on routing table size (Hannes Frederic Sowa) [1177581 1112946]
- [scsi] bnx2fc: fix tgt spinlock locking (Maurizio Lombardi) [1179098 1079656]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.12.2.el6", rls:"OracleLinux6"))) {
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
