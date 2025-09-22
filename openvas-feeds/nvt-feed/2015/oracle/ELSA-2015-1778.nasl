# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123005");
  script_cve_id("CVE-2014-9585", "CVE-2015-0275", "CVE-2015-1333", "CVE-2015-3212", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366");
  script_tag(name:"creation_date", value:"2015-10-06 06:46:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1778)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1778");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1778.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-1778 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-229.14.1.OL7]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-229.14.1]
- [s390] zcrypt: Fixed reset and interrupt handling of AP queues (Hendrik Brueckner) [1248381 1238230]

[3.10.0-229.13.1]
- [dma] ioat: fix tasklet tear down (Herton R. Krzesinski) [1251523 1210093]
- [drm] radeon: Fix VGA switcheroo problem related to hotplug (missing hunk) (Rob Clark) [1207879 1223472]
- [security] keys: Ensure we free the assoc array edit if edit is valid (David Howells) [1246039 1244171] {CVE-2015-1333}
- [net] tcp: properly handle stretch acks in slow start (Florian Westphal) [1243903 1151756]
- [net] tcp: fix no cwnd growth after timeout (Florian Westphal) [1243903 1151756]
- [net] tcp: increase throughput when reordering is high (Florian Westphal) [1243903 1151756]
- [of] Fix sysfs_dirent cache integrity issue (Gustavo Duarte) [1249120 1225539]
- [tty] vt: don't set font mappings on vc not supporting this (Jarod Wilson) [1248384 1213538]
- [scsi] fix regression in scsi_send_eh_cmnd() (Ewan Milne) [1243412 1167454]
- [net] udp: fix behavior of wrong checksums (Denys Vlasenko) [1240760 1240761] {CVE-2015-5364 CVE-2015-5366}
- [fs] Convert MessageID in smb2_hdr to LE (Sachin Prabhu) [1238693 1161441]
- [x86] bpf_jit: fix compilation of large bpf programs (Denys Vlasenko) [1236938 1236939] {CVE-2015-4700}
- [net] sctp: fix ASCONF list handling (Marcelo Leitner) [1227960 1206474] {CVE-2015-3212}
- [fs] ext4: allocate entire range in zero range (Lukas Czerner) [1193909 1187071] {CVE-2015-0275}
- [x86] ASLR bruteforce possible for vdso library (Jacob Tanenbaum) [1184898 1184899] {CVE-2014-9585}

[3.10.0-229.12.1]
- [ethernet] ixgbe: remove CIAA/D register reads from bad VF check (John Greene) [1245597 1205903]
- [kernel] sched: Avoid throttle_cfs_rq() racing with period_timer stopping (Rik van Riel) [1241078 1236413]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.14.1.el7", rls:"OracleLinux7"))) {
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
