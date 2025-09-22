# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0852.1");
  script_cve_id("CVE-2021-4203", "CVE-2022-2991", "CVE-2022-36280", "CVE-2022-38096", "CVE-2022-4129", "CVE-2023-0045", "CVE-2023-0590", "CVE-2023-23559", "CVE-2023-26545");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 19:29:19 +0000 (Mon, 23 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0852-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230852-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209188");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/014114.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2022-4129: Fixed a denial of service with the Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing sk_user_data can lead to a race condition and NULL pointer dereference. (bsc#1205711)
- CVE-2021-4203: Fixed use-after-free read flaw that was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and SO_PEERGROUPS race with listen() (bsc#1194535).
- CVE-2023-23559: Fixed integer overflow in rndis_wlan that leads to a buffer overflow (bsc#1207051).
- CVE-2023-26545: Fixed double free in net/mpls/af_mpls.c upon an allocation failure (bsc#1208700).
- CVE-2022-38096: Fixed NULL-ptr deref in vmw_cmd_dx_define_query() (bsc#1203331).
- CVE-2022-36280: Fixed out-of-bounds memory access vulnerability found in vmwgfx driver (bsc#1203332).
- CVE-2023-0045: Fixed missing Flush IBP in ib_prctl_set (bsc#1207773).
- CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
- CVE-2022-2991: Fixed an heap-based overflow in the lightnvm implemenation (bsc#1201420).

The following non-security bugs were fixed:

- kabi/severities: add l2tp local symbols");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.120.4", rls:"SLES12.0SP4"))) {
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
