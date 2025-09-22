# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123528");
  script_cve_id("CVE-2012-6542", "CVE-2012-6545", "CVE-2013-0343", "CVE-2013-1928", "CVE-2013-1929", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-2851", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-3231", "CVE-2013-4345", "CVE-2013-4387", "CVE-2013-4591", "CVE-2013-4592");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:06 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1645)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1645");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1645.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-1645 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-431]
- [md] Disabling of TRIM on RAID5 for RHEL6.5 was too aggressive (Jes Sorensen) [1028426]

[2.6.32-430]
- [x86] Revert 'efi: be more paranoid about available space when creating variables' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efivars: firmware bug workarounds should be in platform code' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Export efi_query_variable_store() for efivars.ko' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Check max_size only if it is non-zero' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Distinguish between 'remaining space' and actually used space' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Implement efi_no_storage_paranoia parameter' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'Modify UEFI anti-bricking code' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Fix dummy variable buffer allocation' (Rafael Aquini) [1012370 1023173]

[2.6.32-429]
- [fs] revert xfs: prevent deadlock trying to cover an active log (Eric Sandeen) [1014867]

[2.6.32-428]
- [fs] Revert 'vfs: allow umount to handle mountpoints without revalidating them' (Rafael Aquini) [1024607]
- [fs] Revert 'vfs: massage umount_lookup_last() a bit to reduce nesting' (Rafael Aquini) [1024607]
- [fs] Revert 'vfs: rename user_path_umountat() to user_path_mountpoint_at()' (Rafael Aquini) [1024607]
- [fs] Revert 'vfs: introduce kern_path_mountpoint()' (Rafael Aquini) [1024607]
- [fs] Revert 'autofs4: fix device ioctl mount lookup' (Rafael Aquini) [1024607]

[2.6.32-427]
- [tools] perf: Add ref-cycles into array of tested events (Jiri Olsa) [968806]
- [pci] Revert 'make SRIOV resources optional' (Myron Stowe) [1022270]
- [pci] Revert 'ability to relocate assigned pci-resources' (Myron Stowe) [1022270]
- [pci] Revert 'honor child buses add_size in hot plug configuration' (Myron Stowe) [1022270]
- [pci] Revert 'make cardbus-bridge resources optional' (Myron Stowe) [1022270]
- [pci] Revert 'code and comments cleanup' (Myron Stowe) [1022270]
- [pci] Revert 'make re-allocation try harder by reassigning ranges higher in the heirarchy' (Myron Stowe) [1022270]
- [pci] Revert 'Calculate right add_size' (Myron Stowe) [1022270]

[2.6.32-426]
- [block] loop: unplug_fn only when backing file is attached (Lukas Czerner) [1022997]
- [fs] ext4: Remove warning from ext4_da_update_reserve_space() (Lukas Czerner) [1011876]
- [kernel] async: Revert MAX_THREADS to 256 (Neil Horman) [1021705]
- [net] ipv6: restrict neighbor entry creation to output flow (Jiri Pirko) [997103]
- [net] ipv6: udp packets following an UFO enqueued packet need also be handled by UFO (Jiri Pirko) [1011930] {CVE-2013-4387}
- [net] ipv4: blackhole route should always be recalculated (Herbert Xu) [1010347]
- [net] unix: revert/fix race in stream sockets with SOCK_PASS* flags (Daniel Borkmann) [1019343]
- [net] Loosen constraints for recalculating checksum in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.el6", rls:"OracleLinux6"))) {
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
