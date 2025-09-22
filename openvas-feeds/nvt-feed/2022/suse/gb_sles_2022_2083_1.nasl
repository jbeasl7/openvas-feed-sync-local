# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2083.1");
  script_cve_id("CVE-2019-20811", "CVE-2021-20292", "CVE-2021-20321", "CVE-2021-33061", "CVE-2021-38208", "CVE-2021-39711", "CVE-2021-43389", "CVE-2022-1011", "CVE-2022-1353", "CVE-2022-1419", "CVE-2022-1516", "CVE-2022-1652", "CVE-2022-1734", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21166", "CVE-2022-21180", "CVE-2022-30594");
  script_tag(name:"creation_date", value:"2022-06-15 04:32:10 +0000 (Wed, 15 Jun 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-10 16:36:37 +0000 (Fri, 10 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2083-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2083-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222083-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199650");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-June/011291.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2083-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated.

The following security bugs were fixed:

- CVE-2022-21127: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21123: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21125: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21180: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-21166: Fixed a stale MMIO data transient which can be exploited to speculatively/transiently disclose information via spectre like attacks. (bsc#1199650)
- CVE-2022-1652: Fixed a statically allocated error counter inside the floppy kernel module (bsc#1199063).
- CVE-2022-1734: Fixed a r/w use-after-free when non synchronized between cleanup routine and firmware download routine. (bnc#1199605)
- CVE-2021-39711: Fixed a possible out of bounds read due to Incorrect Size Value. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation (bnc#1197219).
- CVE-2022-30594: Fixed restriction bypass on setting the PT_SUSPEND_SECCOMP flag (bnc#1199505).
- CVE-2021-33061: Fixed insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters that may have allowed an authenticated user to potentially enable denial of service via local access (bnc#1196426).
- CVE-2022-1516: Fixed null-ptr-deref caused by x25_disconnect (bsc#1199012).
- CVE-2021-20321: Fixed a race condition accessing file object in the OverlayFS subsystem in the way users do rename in specific way with OverlayFS. A local user could have used this flaw to crash the system (bnc#1191647).
- CVE-2022-1419: Fixed a concurrency use-after-free in vgem_gem_dumb_create (bsc#1198742).
- CVE-2021-43389: Fixed an array-index-out-of-bounds flaw in the detach_capi_ctr function in drivers/isdn/capi/kcapi.c (bnc#1191958).
- CVE-2019-20811: Fixed issue in rx_queue_add_kobject() and netdev_queue_add_kobject() in net/core/net-sysfs.c, where a reference count is mishandled (bnc#1172456).
- CVE-2021-38208: Fixed a denial of service (NULL pointer dereference and BUG) by making a getsockname call after a certain type of failure of a bind call (bnc#1187055).
- CVE-2022-1353: Fixed access control to kernel memory in the pfkey_register function in net/key/af_key.c. (bnc#1198516)
- CVE-2021-20292: Fixed object validation prior to performing operations on the object in nouveau_sgdma_create_ttm in Nouveau DRM subsystem (bnc#1183723).
- CVE-2022-1011: Fixed an use-after-free vulnerability ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.99.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.99.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.99.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.99.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.99.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.99.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.99.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.99.2", rls:"SLES12.0SP4"))) {
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
