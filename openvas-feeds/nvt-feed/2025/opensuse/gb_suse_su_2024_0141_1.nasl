# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0141.1");
  script_cve_id("CVE-2020-26555", "CVE-2023-51779", "CVE-2023-6121", "CVE-2023-6531", "CVE-2023-6546", "CVE-2023-6606", "CVE-2023-6610", "CVE-2023-6622", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 17:15:07 +0000 (Fri, 08 Dec 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0141-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0141-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240141-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218643");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017677.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:0141-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix garbage collector's deletion of SKB races with unix_stream_read_generic()on the socket that the SKB is queued on (bsc#1218447).
- CVE-2023-6610: Fixed an out of bounds read in the SMB client when printing debug information (bsc#1217946).
- CVE-2023-51779: Fixed a use-after-free because of a bt_sock_ioctl race condition in bt_sock_recvmsg (bsc#1218559).
- CVE-2020-26555: Fixed Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B that may permit an unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without knowledge of the PIN (bsc#1179610 bsc#1215237).
- CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving a malformed length from a server (bsc#1217947).
- CVE-2023-6546: Fixed a race condition in the GSM 0710 tty multiplexor via the GSMIOC_SETCONF ioctl that could lead to local privilege escalation (bsc#1218335).
- CVE-2023-6931: Fixed a heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component that could lead to local privilege escalation. (bsc#1218258).
- CVE-2023-6932: Fixed a use-after-free vulnerability in the Linux kernel's ipv4: igmp component that could lead to local privilege escalation (bsc#1218253).
- CVE-2023-6622: Fixed a null pointer dereference vulnerability in nft_dynset_init() that could allow a local attacker with CAP_NET_ADMIN user privilege to trigger a denial of service (bsc#1217938).
- CVE-2023-6121: Fixed an out-of-bounds read vulnerability in the NVMe-oF/TCP subsystem that could lead to information leak (bsc#1217250).

The following non-security bugs were fixed:

- Documentation: KVM: add separate directories for architecture-specific documentation (jsc#PED-7167).
- Documentation: KVM: update amd-memory-encryption.rst references (jsc#PED-7167).
- Documentation: KVM: update msr.rst reference (jsc#PED-7167).
- Documentation: KVM: update s390-diag.rst reference (jsc#PED-7167).
- Documentation: KVM: update s390-pv.rst reference (jsc#PED-7167).
- Documentation: drop more IDE boot options and ide-cd.rst (git-fixes).
- Documentation: qat: Use code block for qat sysfs example (git-fixes).
- Drop Documentation/ide/ (git-fixes).
- Fix crash on screen resize (bsc#1218229)
- Fix drm gem object underflow (bsc#1218092)
- Revert 'Limit kernel-source-azure build to architectures for which we build binaries (bsc#1108281).'
- Revert 'PCI/ASPM: Remove pcie_aspm_pm_state_change()' (git-fixes).
- Revert 'PCI: acpiphp: Reassign resources on bridge if necessary' (git-fixes).
- Revert 'md: unlock mddev before reap sync_thread in action_store' (git-fixes).
- Revert 'swiotlb: panic if nslabs is too small' (git-fixes).
- Revert 'xhci: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure", rpm:"cluster-md-kmp-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure", rpm:"dlm-kmp-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure", rpm:"gfs2-kmp-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-livepatch-devel", rpm:"kernel-azure-livepatch-devel~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional", rpm:"kernel-azure-optional~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-vdso", rpm:"kernel-azure-vdso~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure", rpm:"kselftests-kmp-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure", rpm:"ocfs2-kmp-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure", rpm:"reiserfs-kmp-azure~5.14.21~150500.33.29.1", rls:"openSUSELeap15.5"))) {
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
