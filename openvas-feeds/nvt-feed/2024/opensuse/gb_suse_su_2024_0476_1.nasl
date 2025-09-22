# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833635");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-33631", "CVE-2023-46838", "CVE-2023-47233", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-51780", "CVE-2023-51782", "CVE-2023-6040", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2023-6915", "CVE-2024-0340", "CVE-2024-0565", "CVE-2024-0641", "CVE-2024-0775", "CVE-2024-1085", "CVE-2024-1086", "CVE-2024-24860");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:51:47 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:0476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0476-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A32IXEPKHZVYVUQUUNYVHL3LMIXJMR7P");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:0476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2024-0340: Fixed information disclosure in vhost/vhost.c:vhost_new_msg()
      (bsc#1218689).

  * CVE-2024-24860: Fixed a denial of service caused by a race condition in
      {min, max}_key_size_set() (bsc#1219608).

  * CVE-2024-1085: Fixed nf_tables use-after-free vulnerability in the
      nft_setelem_catchall_deactivate() function (bsc#1219429).

  * CVE-2024-1086: Fixed a use-after-free vulnerability inside the nf_tables
      component that could have been exploited to achieve local privilege
      escalation (bsc#1219434).

  * CVE-2023-51042: Fixed use-after-free in amdgpu_cs_wait_all_fences in
      drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c (bsc#1219128).

  * CVE-2023-51780: Fixed a use-after-free in do_vcc_ioctl in net/atm/ioctl.c,
      because of a vcc_recvmsg race condition (bsc#1218730).

  * CVE-2023-46838: Fixed an issue with Xen netback processing of zero-length
      transmit fragment (bsc#1218836).

  * CVE-2021-33631: Fixed an integer overflow in ext4_write_inline_data_end()
      (bsc#1219412).

  * CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request
      (bsc#1217988).

  * CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete
      (bsc#1217989).

  * CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec
      (bsc#1217987).

  * CVE-2023-47233: Fixed a use-after-free in the device unplugging (disconnect
      the USB by hotplug) code inside the brcm80211 component (bsc#1216702).

  * CVE-2023-51043: Fixed use-after-free during a race condition between a
      nonblocking atomic commit and a driver unload in
      drivers/gpu/drm/drm_atomic.c (bsc#1219120).

  * CVE-2024-0775: Fixed use-after-free in __ext4_remount in fs/ext4/super.c
      that could allow a local user to cause an information leak problem while
      freeing the old quota file names before a potential failure (bsc#1219053).

  * CVE-2023-6040: Fixed an out-of-bounds access vulnerability while creating a
      new netfilter table, lack of a safeguard against invalid nf_tables family
      (pf) values within `nf_tables_newtable` function (bsc#1218752).

  * CVE-2024-0641: Fixed a denial of service vulnerability in
      tipc_crypto_key_revoke in net/tipc/crypto.c (bsc#1218916).

  * CVE-2024-0565: Fixed an out-of-bounds memory read flaw in
      receive_encrypted_standard in fs/smb/client/smb2ops.c (bsc#1218832).

  * CVE-2023-69 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.68.1", rls:"openSUSELeapMicro5.4"))) {
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