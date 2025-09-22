# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0160.1");
  script_cve_id("CVE-2020-26555", "CVE-2023-51779", "CVE-2023-6121", "CVE-2023-6531", "CVE-2023-6546", "CVE-2023-6606", "CVE-2023-6610", "CVE-2023-6622", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-08 17:15:07 +0000 (Fri, 08 Dec 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0160-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240160-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214158");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218738");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017686.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:0160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-26555: Fixed Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B that may permit an unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without knowledge of the PIN (bsc#1179610 bsc#1215237).
- CVE-2023-51779: Fixed a use-after-free because of a bt_sock_ioctl race condition in bt_sock_recvmsg (bsc#1218559).
- CVE-2023-6121: Fixed an out-of-bounds read vulnerability in the NVMe-oF/TCP subsystem that could lead to information leak (bsc#1217250).
- CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix garbage collector's deletion of SKB races with unix_stream_read_generic()on the socket that the SKB is queued on (bsc#1218447).
- CVE-2023-6546: Fixed a race condition in the GSM 0710 tty multiplexor via the GSMIOC_SETCONF ioctl that could lead to local privilege escalation (bsc#1218335).
- CVE-2023-6606: Fixed an out-of-bounds read vulnerability in smbCalcSize in fs/smb/client/netmisc.c that could allow a local attacker to crash the system or leak internal kernel information (bsc#1217947).
- CVE-2023-6610: Fixed an out-of-bounds read vulnerability in smb2_dump_detail in fs/smb/client/smb2ops.c that could allow a local attacker to crash the system or leak internal kernel information (bsc#1217946).
- CVE-2023-6622: Fixed a null pointer dereference vulnerability in nft_dynset_init() that could allow a local attacker with CAP_NET_ADMIN user privilege to trigger a denial of service (bsc#1217938).
- CVE-2023-6931: Fixed a heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component that could lead to local privilege escalation. (bsc#1218258).
- CVE-2023-6932: Fixed a use-after-free vulnerability in the Linux kernel's ipv4: igmp component that could lead to local privilege escalation (bsc#1218253).


The following non-security bugs were fixed:

- Documentation: KVM: add separate directories for architecture-specific documentation (jsc#PED-7167).
- Documentation: KVM: update amd-memory-encryption.rst references (jsc#PED-7167).
- Documentation: KVM: update msr.rst reference (jsc#PED-7167).
- Documentation: KVM: update s390-diag.rst reference (jsc#PED-7167).
- Documentation: KVM: update s390-pv.rst reference (jsc#PED-7167).
- Documentation: drop more IDE boot options and ide-cd.rst (git-fixes).
- Documentation: qat: Use code block for qat sysfs example (git-fixes).
- Drop Documentation/ide/ (git-fixes).
- Fix crash in vmw_context_cotables_unref when 3d support is enabled (bsc#1218738)
- Fix crash on screen resize (bsc#1218229)
- Fix drm gem object underflow (bsc#1218092)
- Revert 'PCI/ASPM: Remove pcie_aspm_pm_state_change()' (git-fixes).
- Revert 'PCI: acpiphp: Reassign resources on bridge if necessary' (git-fixes).
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.44.1.150500.6.19.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150500.55.44.1.150500.6.19.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.44.1", rls:"openSUSELeap15.5"))) {
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
