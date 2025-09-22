# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3309.1");
  script_cve_id("CVE-2022-40982", "CVE-2023-0459", "CVE-2023-20569", "CVE-2023-20593", "CVE-2023-2985", "CVE-2023-35001", "CVE-2023-3567", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3776");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:26:27 +0000 (Mon, 31 Jul 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3309-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3309-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233309-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962880");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-August/015902.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:3309-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2023-20593: Fixed a ZenBleed issue in 'Zen 2' CPUs that could allow an attacker to potentially access sensitive information (bsc#1213286).
- CVE-2023-2985: Fixed an use-after-free vulnerability in hfsplus_put_super in fs/hfsplus/super.c that could allow a local user to cause a denial of service (bsc#1211867).
- CVE-2023-35001: Fixed an out-of-bounds memory access flaw in nft_byteorder that could allow a local attacker to escalate their privilege (bsc#1213059).
- CVE-2022-40982: A transient execution attack called 'Gather Data Sampling' affecting is mitigated, together with respective Intel CPU Microcode updates (bsc#1206418, CVE-2022-40982).
- CVE-2023-0459: Fixed that copy_from_user on 64-bit versions of the Linux kernel did not implement the __uaccess_begin_nospec allowing a user to bypass the 'access_ok' check which could be used to leak information (bsc#1211738).
- CVE-2023-20569: A side channel attack known as 'Inception' or 'RAS Poisoning' may allow an attacker to influence branch prediction, potentially leading to information disclosure. (bsc#1213287).
- CVE-2023-3567: A use-after-free flaw was found in vcs_read in drivers/tty/vt/vc_screen.c in vc_screen. This flaw allowed an attacker with local user access to cause a system crash or leak internal kernel information (bsc#1213167bsc#1213842).
- CVE-2023-3609: A use-after-free vulnerability was fixed in net/sched: cls_u32 component can be exploited to achieve local privilege escalation. If tcf_change_indev() fails, u32_set_parms() will immediately return an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can control the reference counter and set it to zero, they can cause the reference to be freed, leading to a use-after-free vulnerability. (bsc#1213586).
- CVE-2023-3611: An out-of-bounds write vulnerability was fixed in net/sched: sch_qfq component can be exploited to achieve local privilege escalation. The qfq_change_agg() function in net/sched/sch_qfq.c allowed an out-of-bounds write because lmax is updated according to packet sizes without bounds checks. (bsc#1213585).
- CVE-2023-3776: A use-after-free vulnerability was fixed in net/sched: cls_fw component can be exploited to achieve local privilege escalation. If tcf_change_indev() fails, fw_set_parms() will immediately return an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can control the reference counter and set it to zero, they can cause the reference to be freed, leading to a use-after-free vulnerability. (bsc#1213588).

The following non-security bugs were fixed:

- Fix double fget() in vhost_net_set_backend() (git-fixes).
- NFSv4.1: Always send a RECLAIM_COMPLETE after establishing lease (git-fixes).
- SUNRPC: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.173.1", rls:"SLES12.0SP5"))) {
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
