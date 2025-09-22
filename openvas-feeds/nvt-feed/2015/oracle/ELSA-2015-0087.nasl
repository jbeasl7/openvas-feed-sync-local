# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123193");
  script_cve_id("CVE-2014-4656", "CVE-2014-7841");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-0087)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0087");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0087.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-0087 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-504.8.1]
- [crypto] crc32c: Kill pointless CRYPTO_CRC32C_X86_64 option (Jarod Wilson) [1175509 1036212]
- [crypto] testmgr: add larger crc32c test vector to test FPU path in crc32c_intel (Jarod Wilson) [1175509 1036212]
- [crypto] tcrypt: Added speed test in tcrypt for crc32c (Jarod Wilson) [1175509 1036212]
- [crypto] crc32c: Optimize CRC32C calculation with PCLMULQDQ instruction (Jarod Wilson) [1175509 1036212]
- [crypto] crc32c: Rename crc32c-intel.c to crc32c-intel_glue.c (Jarod Wilson) [1175509 1036212]

[2.6.32-504.7.1]
- [kernel] ipc/sem: Fully initialize sem_array before making it visible (Rik van Riel) [1172029 1165277]
- [kernel] ipc/sem: synchronize semop and semctl with IPC_RMID (Rik van Riel) [1172029 1165277]
- [kernel] ipc/sem: update sem_otime for all operations (Larry Woodman) [1172025 1168588]
- [fs] fuse: prevent null and panic on dentry revalidate (Brian Foster) [1172022 1162782]
- [net] netfilter: ipset: timeout values corrupted on set resize (Marcelo Leitner) [1172764 1152754]
- [net] netfilter: fix xt_TCPOPTSTRIP in forwarding path (Marcelo Leitner) [1172027 1135650]
- [usb] ehci: Fix panic on hotplug race coandition (Don Zickus) [1172024 1107010]
- [usb] usb_wwan: replace release and disconnect with a port_remove hook (Stanislaw Gruszka) [1172030 1148615]
- [x86] traps: stop using IST for #SS (Petr Matousek) [1172810 1172811] {CVE-2014-9322}

[2.6.32-504.6.1]
- [fs] ext4: don't count external journal blocks as overhead (Eric Saandeen) [1168504 1163811]
- [net] sctp: fix NULL pointer dereference in af->from_addr_param on malformed packet (Daniel Borkmann) [1163090 1153980] {CVE-2014-7841}
- [netdrv] e100: fix typo in MDI/MDI-X eeprom check in e100_phy_init (John Greene) [1165985 1156417]
- [powerpc] Add smp_mb()s to arch_spin_unlock_wait() (Gustavo Duarte) [1165986 1136224]
- [powerpc] Add smp_mb() to arch_spin_is_locked() (Gustavo Duarte) [1165986 1136224]
- [kernel] cpuset: PF_SPREAD_PAGE and PF_SPREAD_SLAB should be atomic flags (Aaron Tomlin) [1165002 1045310]
- [documentation] cpuset: Update the cpuset flag file (Aaron Tomlin) [1165002 1045310]
- [alsa] control: Make sure that id->iandex does not overflow (Jacob Tanenbaum) [1149140 1117312] {CVE-2014-4656}
- [alsa] control: Handle numid overflow (Jacob Tanenbaum) [1149140 1117312] {CVE-2014-4656}
- [s390] mm: fix SIGBUS handling (Heandrik Brueckner) [1169433 1145070]
- [fs] gfs2: fix bad inode i_goal values during block allocation (Abhijith Das) [1165001 1130684]
- [md] dm-thin: fix pool_io_hints to avoid looking at max_hw_sectors (Mike Snitzer) [1161420 1161421 1142773 1145230]

[2.6.32-504.5.1]
- [fs] nfsd: don't halt scanning the DRC LRU list when there's an RC_INPROG entry (J. Bruce Fields) [1168129 1150675]

[2.6.32-504.4.1]
- [fs] nfs: Make sure pre_change_attr is initialized correctly (Scott Mayhew) [1163214 1160042]
- [usb] ehci: Fix a regression in the ISO scheduler (Gustavo Duarte) [1162072 1145805]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.8.1.el6", rls:"OracleLinux6"))) {
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
