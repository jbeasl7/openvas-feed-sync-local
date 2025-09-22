# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833381");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-19083", "CVE-2022-3105", "CVE-2022-3106", "CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3111", "CVE-2022-3112", "CVE-2022-3115", "CVE-2022-3435", "CVE-2022-3564", "CVE-2022-3643", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-4662", "CVE-2022-47520", "CVE-2022-47929", "CVE-2023-0266", "CVE-2023-23454", "CVE-2023-23455");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 21:47:38 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:44:00 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:0152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0152-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RPZHPAK4NX3NLGCWJJEEEQQHOCTJVAFQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:0152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various
     security and bugfixes.

     The following security bugs were fixed:

  - CVE-2023-0266: Fixed a use-after-free bug led by a missing lock in ALSA.
       (bsc#1207134)

  - CVE-2022-47929: Fixed a NULL pointer dereference bug in the traffic
       control subsystem which allowed an unprivileged user to trigger a denial
       of service via a crafted traffic control configuration. (bsc#1207237)

  - CVE-2023-23454: Fixed a type-confusion in the CBQ network scheduler
       (bsc#1207036)

  - CVE-2023-23455: Fixed a bug that could allow attackers to cause a denial
       of service because of type confusion in atm_tc_enqueue. (bsc#1207125)

  - CVE-2022-3435: Fixed an out-of-bounds read in fib_nh_match() of the file
       net/ipv4/fib_semantics.c (bsc#1204171).

  - CVE-2022-4662: Fixed a recursive locking violation in usb-storage that
       can cause the kernel to deadlock. (bsc#1206664)

  - CVE-2022-3115: Fixed a null pointer dereference in malidp_crtc.c caused
       by a lack of checks of the return value of kzalloc. (bsc#1206393)

  - CVE-2022-47520: Fixed an out-of-bounds read when parsing a Robust
       Security Network (RSN) information element from a Netlink packet.
       (bsc#1206515)

  - CVE-2022-3112: Fixed a  null pointer dereference caused by lacks check
       of the return value of kzalloc() in vdec_helpers.c:amvdec_set_canvases.
       (bsc#1206399)

  - CVE-2022-3564: Fixed a bug which could lead to use after free, it was
       found in the function l2cap_reassemble_sdu of the file
       net/bluetooth/l2cap_core.c of the component Bluetooth. (bsc#1206073)

  - CVE-2022-3108: Fixed a bug in kfd_parse_subtype_iolink in
       drivers/gpu/drm/amd/amdkfd/kfd_crat.c where a lack of check of the
       return value of kmemdup() could lead to a NULL pointer dereference.
       (bsc#1206389)

  - CVE-2019-19083: Fixed a memory leaks in clock_source_create that could
       allow attackers to cause a denial of service (bsc#1157049).

  - CVE-2022-42328: Fixed a bug which could allow guests to trigger denial
       of service via the netback driver (bsc#1206114).

  - CVE-2022-42329: Fixed a bug which could allow guests to trigger denial
       of service via the netback driver (bsc#1206113).

  - CVE-2022-3643: Fixed a bug which could allow guests to trigger NIC
       interface reset/abort/crash via netback driver (bsc#1206113).

  - CVE-2022-3107: Fixed a null pointer dereference caused by a missing
       check of the return ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.2.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"dtb-al", rpm:"dtb-al~5.3.18~150300.59.109.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-zte", rpm:"dtb-zte~5.3.18~150300.59.109.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-al", rpm:"dtb-al~5.3.18~150300.59.109.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-zte", rpm:"dtb-zte~5.3.18~150300.59.109.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.109.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.109.1.150300.18.62.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.3.18~150300.59.109.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.3.18~150300.59.109.1", rls:"openSUSELeapMicro5.2"))) {
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