# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4347.1");
  script_cve_id("CVE-2020-36766", "CVE-2023-1192", "CVE-2023-1206", "CVE-2023-1859", "CVE-2023-31085", "CVE-2023-34324", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-40283", "CVE-2023-42754", "CVE-2023-45862", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4881", "CVE-2023-4921");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 19:38:11 +0000 (Thu, 14 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4347-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4347-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234347-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216051");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2023-November/032577.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4347-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2023-31085: Fixed a divide-by-zero error in do_div(sz,mtd->erasesize) that could cause a local DoS. (bsc#1210778)
- CVE-2023-45862: Fixed an issue in the ENE UB6250 reader driver whwere an object could potentially extend beyond the end of an allocation causing. (bsc#1216051)
- CVE-2023-34324: Fixed a possible deadlock in Linux kernel event handling. (bsc#1215745).
- CVE-2023-39189: Fixed a flaw in the Netfilter subsystem that could allow a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, leading to a crash or information disclosure. (bsc#1216046)
- CVE-2023-39194: Fixed an out of bounds read in the XFRM subsystem (bsc#1215861).
- CVE-2023-39193: Fixed an out of bounds read in the xtables subsystem (bsc#1215860).
- CVE-2023-39192: Fixed an out of bounds read in the netfilter (bsc#1215858).
- CVE-2023-42754: Fixed a NULL pointer dereference in the IPv4 stack that could lead to denial of service (bsc#1215467).
- CVE-2023-1206: Fixed a hash collision flaw in the IPv6 connection lookup table which could be exploited by network adjacent attackers, increasing CPU usage by 95% (bsc#1212703).
- CVE-2023-4921: Fixed a use-after-free vulnerability in the QFQ network scheduler which could be exploited to achieve local privilege escalation (bsc#1215275).
- CVE-2023-4622: Fixed a use-after-free vulnerability in the Unix domain sockets component which could be exploited to achieve local privilege escalation (bsc#1215117).
- CVE-2023-4623: Fixed a use-after-free issue in the HFSC network scheduler which could be exploited to achieve local privilege escalation (bsc#1215115).
- CVE-2020-36766: Fixed a potential information leak in in the CEC driver (bsc#1215299).
- CVE-2023-1859: Fixed a use-after-free flaw in Xen transport for 9pfs which could be exploited to crash the system (bsc#1210169).
- CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem that could lead to potential information disclosure or a denial of service (bsc#1215221).
- CVE-2023-40283: Fixed use-after-free in l2cap_sock_ready_cb (bsc#1214233).
- CVE-2023-1192: Fixed use-after-free in cifs_demultiplex_thread() (bsc#1208995).

The following non-security bugs were fixed:

- check-for-config-changes: ignore BUILTIN_RETURN_ADDRESS_STRIPS_PAC (bsc#1214380). gcc7 on SLE 15 does not support this while later gcc does.
- mkspec: Allow unsupported KMPs (bsc#1214386)
- old-flavors: Drop 2.6 kernels. 2.6 based kernels are EOL, upgrading from them is no longer suported.");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150100.197.160.1", rls:"SLES15.0SP1"))) {
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
