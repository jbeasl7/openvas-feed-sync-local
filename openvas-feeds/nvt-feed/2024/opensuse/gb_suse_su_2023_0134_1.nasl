# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833721");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2019-19083", "CVE-2022-3105", "CVE-2022-3106", "CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3111", "CVE-2022-3435", "CVE-2022-3643", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-4662");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-08 17:29:14 +0000 (Mon, 08 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:50:38 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:0134-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.2");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0134-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EINMIUJHMJIMEOPPSVPN7NZCT2Y7MGZN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:0134-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various
     security and bugfixes.

     The following security bugs were fixed:

  - CVE-2022-3435: Fixed an out-of-bounds read in fib_nh_match() of the file
       net/ipv4/fib_semantics.c (bsc#1204171).

  - CVE-2022-4662: Fixed a recursive locking violation in usb-storage that
       can cause the kernel to deadlock. (bsc#1206664)

  - CVE-2022-3105: Fixed a null pointer dereference caused by a missing
       check of the return value of kmalloc_array. (bsc#1206398)

  - CVE-2022-3108: Fixed a bug in kfd_parse_subtype_iolink in
       drivers/gpu/drm/amd/amdkfd/kfd_crat.c where a lack of check of the
       return value of kmemdup() could lead to a NULL pointer dereference.
       (bsc#1206389)

  - CVE-2022-3106: Fixed a null pointer dereference caused by a missing
       check of the return value of kmalloc. (bsc#1206397)

  - CVE-2022-3107: Fixed a null pointer dereference caused by a missing
       check of the return value of kvmalloc_array. (bsc#1206395)

  - CVE-2022-3111: Fixed a missing release of resource after effective
       lifetime bug caused by a missing free of the WM8350_IRQ_CHG_FAST_RDY in
       wm8350_init_charger. (bsc#1206394)

  - CVE-2022-42328: Fixed a bug which could allow guests to trigger denial
       of service via the netback driver (bsc#1206114).

  - CVE-2022-42329: Fixed a bug which could allow guests to trigger denial
       of service via the netback driver (bsc#1206113).

  - CVE-2022-3643: Fixed a bug which could allow guests to trigger NIC
       interface reset/abort/crash via netback driver (bsc#1206113).

  - CVE-2019-19083: Fixed a memory leaks in clock_source_create that could
       allow attackers to cause a denial of service (bsc#1157049).

     The following non-security bugs were fixed:

  - afs: Fix some tracing details (git-fixes).

  - block: Do not reread partition table on exclusively open device
       (bsc#1190969).

  - cuse: prevent clone (bsc#1206177).

  - dt-bindings: clocks: imx8mp: Add ID for usb suspend clock (git-fixes).

  - efi: Add iMac Pro 2017 to uefi skip cert quirk (git-fixes).

  - fuse: do not check refcount after stealing page (bsc#1206174).

  - fuse: fix the - direct_IO() treatment of iov_iter (bsc#1206176).

  - fuse: fix use after free in fuse_read_interrupt() (bsc#1206178).

  - fuse: lock inode unconditionally in fuse_fallocate() (bsc#1206179).

  - fuse: update attr_version counter on fuse_notify_inval_inode()
       (bsc#1206175).

  - ipv6: ping: fix wrong checksum for large ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap Micro 5.2.");

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

if(release == "openSUSELeapMicro5.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~150300.115.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~150300.115.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~150300.115.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~150300.115.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~150300.115.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~150300.115.1", rls:"openSUSELeapMicro5.2"))) {
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