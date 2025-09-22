# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1744.1");
  script_cve_id("CVE-2018-16871", "CVE-2019-12614", "CVE-2019-12817");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 15:36:15 +0000 (Tue, 06 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1744-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191744-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.

This update adds support for the Hygon Dhyana CPU (fate#327735).

The following security bugs were fixed:
CVE-2019-12614: An issue was discovered in dlpar_parse_cc_property in
 arch/powerpc/platforms/pseries/dlpar.c. There was an unchecked kstrdup
 of prop->name, which might allow an attacker to cause a denial of
 service (NULL pointer dereference and system crash) (bnc#1137194).

CVE-2018-16871: A NULL pointer dereference due to an anomalized NFS
 message sequence was fixed. (bnc#1137103).

CVE-2019-12817: On the PowerPC architecture, local attackers could
 access other users processes memory (bnc#1138263).

The following non-security bugs were fixed:
6lowpan: Off by one handling ->nexthdr (bsc#1051510).

acpi: Add Hygon Dhyana support (fate#327735).

af_key: unconditionally clone on broadcast (bsc#1051510).

alsa: firewire-motu: fix destruction of data for isochronous resources
 (bsc#1051510).

alsa: hda/realtek - Update headset mode for ALC256 (bsc#1051510).

alsa: oxfw: allow PCM capture for Stanton SCS.1m (bsc#1051510).

ASoC: cs42xx8: Add regcache mask dirty (bsc#1051510).

ASoC: fsl_asrc: Fix the issue about unsupported rate (bsc#1051510).

audit: fix a memory leak bug (bsc#1051510).

blk-mq: fix hang caused by freeze/unfreeze sequence (bsc#1128432).

ceph: factor out ceph_lookup_inode() (bsc#1138681).

ceph: fix NULL pointer deref when debugging is enabled (bsc#1138681).

ceph: fix potential use-after-free in ceph_mdsc_build_path (bsc#1138681).

ceph: flush dirty inodes before proceeding with remount (bsc#1138681).

ceph: print inode number in __caps_issued_mask debugging messages
 (bsc#1138681).

ceph: quota: fix quota subdir mounts (bsc#1138681).

ceph: remove duplicated filelock ref increase (bsc#1138681).

cfg80211: fix memory leak of wiphy device name (bsc#1051510).

cpufreq: Add Hygon Dhyana support (fate#327735).

cpufreq: AMD: Ignore the check for ProcFeedback in ST/CZ (fate#327735).

cpu/topology: Export die_id (jsc#SLE-5454).

Do not restrict NFSv4.2 on openSUSE (bsc#1138719).

drbd: Avoid Clang warning about pointless switch statment (bsc#1051510).

drbd: disconnect, if the wrong UUIDs are attached on a connected peer
 (bsc#1051510).

drbd: narrow rcu_read_lock in drbd_sync_handshake (bsc#1051510).

drbd: skip spurious timeout (ping-timeo) when failing promote
 (bsc#1051510).

drivers: depend on HAS_IOMEM for devm_platform_ioremap_resource()
 (bsc#1136333 jsc#SLE-4994).

drivers: fix a typo in the kernel doc for
 devm_platform_ioremap_resource() (bsc#1136333 jsc#SLE-4994).

drivers: provide devm_platform_ioremap_resource() (bsc#1136333
 jsc#SLE-4994).

drivers/rapidio/devices/rio_mport_cdev.c: fix resource leak in error
 handling path in 'rio_dma_transfer()' (bsc#1051510).

drivers/rapidio/rio_cm.c: fix potential oops in riocm_ch_listen()
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.7.1", rls:"SLES15.0SP1"))) {
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
