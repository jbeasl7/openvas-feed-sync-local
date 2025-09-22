# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0785.1");
  script_cve_id("CVE-2018-20669", "CVE-2019-2024", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3819", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8980", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:29 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0785-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190785-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-2024: A use-after-free when disconnecting a source was fixed
 which could lead to crashes. bnc#1129179).

CVE-2019-9213: expand_downwards in mm/mmap.c lacks a check for the mmap
 minimum address, which made it easier for attackers to exploit kernel
 NULL pointer dereferences on non-SMAP platforms. This is related to a
 capability check for the wrong task (bnc#1128166).

CVE-2019-8980: A memory leak in the kernel_read_file function in
 fs/exec.c allowed attackers to cause a denial of service (memory
 consumption) by triggering vfs_read failures (bnc#1126209).

CVE-2019-3819: A flaw was found in the function hid_debug_events_read()
 in drivers/hid/hid-debug.c file which may enter an infinite loop with
 certain parameters passed from a userspace. A local privileged user
 ('root') can cause a system lock up and a denial of service.
 (bnc#1123161).

CVE-2019-8912: af_alg_release() in crypto/af_alg.c neglects to set a
 NULL value for a certain structure member, which leads to a
 use-after-free in sockfs_setattr (bnc#1125907).

CVE-2019-7308: kernel/bpf/verifier.c performed undesirable out-of-bounds
 speculation on pointer arithmetic in various cases, including cases of
 different branches with different state or limits to sanitize, leading
 to side-channel attacks (bnc#1124055).

CVE-2019-3459, CVE-2019-3460: The Bluetooth stack suffered from two
 remote information leak vulnerabilities in the code that handles
 incoming L2cap configuration packets (bsc#1120758).

CVE-2019-7221: The KVM implementation had a Use-after-Free problem
 (bnc#1124732).

CVE-2019-7222: The KVM implementation had an Information Leak
 (bnc#1124735).

CVE-2019-6974: kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandled
 reference counting because of a race condition, leading to a
 use-after-free (bnc#1124728).

CVE-2018-20669: Missing access control checks in ioctl of gpu/drm/i915
 driver were fixed which might have lead to information leaks.
 (bnc#1122971).

The following non-security bugs were fixed:
6lowpan: iphc: reset mac_header after decompress to fix panic
 (bsc#1051510).

9p: clear dangling pointers in p9stat_free (bsc#1051510).

9p locks: fix glock.client_id leak in do_lock (bsc#1051510).

9p/net: fix memory leak in p9_client_create (bsc#1051510).

9p/net: put a lower bound on msize (bsc#1051510).

9p: use inode->i_lock to protect i_size_write() under 32-bit
 (bsc#1051510).

acpi/APEI: Clear GHES block_status before panic() (bsc#1051510).

acpi/device_sysfs: Avoid OF modalias creation for removed device
 (bsc#1051510).

acpi/nfit: Block function zero DSMs (bsc#1051510).

acpi/nfit: Fix Address Range Scrub completion tracking (bsc#1124969).

acpi/nfit: Fix bus command validation (bsc#1051510).

acpi/nfit: Fix command-supported detection ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~5.24.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~5.24.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~5.24.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~5.24.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~5.24.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~5.24.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~5.24.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~5.24.1", rls:"SLES15.0"))) {
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
