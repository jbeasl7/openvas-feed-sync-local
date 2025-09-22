# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3969.1");
  script_cve_id("CVE-2018-3639", "CVE-2018-9517", "CVE-2019-3874", "CVE-2019-3900", "CVE-2020-12770", "CVE-2020-3702", "CVE-2021-0941", "CVE-2021-20320", "CVE-2021-20322", "CVE-2021-22543", "CVE-2021-31916", "CVE-2021-33033", "CVE-2021-34556", "CVE-2021-34981", "CVE-2021-35477", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3656", "CVE-2021-3659", "CVE-2021-3679", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3744", "CVE-2021-3752", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-3760", "CVE-2021-3764", "CVE-2021-3772", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-40490", "CVE-2021-41864", "CVE-2021-42008", "CVE-2021-42252");
  script_tag(name:"creation_date", value:"2021-12-08 03:23:08 +0000 (Wed, 08 Dec 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 18:55:35 +0000 (Thu, 10 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3969-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3969-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213969-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192802");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-December/009871.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3969-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

Unprivileged BPF has been disabled by default to reduce attack surface as too many security issues have happened in the past (jsc#SLE-22573)
 You can re-enable via systemctl setting /proc/sys/kernel/unprivileged_bpf_disabled to 0.
 (kernel.unprivileged_bpf_disabled = 0)

- CVE-2018-3639: Fixed a speculative execution that may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis. (bsc#1087082)
- CVE-2021-20320: Fix a bug that allows a local attacker with special user privilege can circumvent the verifier and may lead to a confidentiality problem. (bsc#1190601)
- CVE-2021-0941: Fixed A missing sanity check to the current MTU check that may allow a local attacker with special user privilege to gain access to out-of-bounds memory leading to a system crash or a leak of internal kernel information. (bnc#1192045)
- CVE-2021-31916: Fixed a bound check failure that could allows an attacker with special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash, a leak of internal kernel information, or a privilege escalation problem. (bnc#1192781)
- CVE-2021-20322: Fixed a bug that provides to an attacker the ability to quickly scan open UDP ports. (bsc#1191790)
- CVE-2021-3772: Fixed an issue that would allow a blind attacker may be able to kill an existing SCTP association through invalid chunks if the attacker knows the IP-addresses and port numbers being used and the attacker can send packets with spoofed IP addresses. (bsc#1190351)
- CVE-2021-34981: Fixed an issue that allows an attacker with a local account to escalate privileges when CAPI (ISDN) hardware connection fails. (bsc#1191961)
- CVE-2018-9517: Fixed possible memory corruption due to a use after free in pppol2tp_connect (bsc#1108488).
- CVE-2019-3874: Fixed possible denial of service attack via SCTP socket buffer used by a userspace applications (bnc#1129898).
- CVE-2019-3900: Fixed an infinite loop issue while handling incoming packets in handle_rx() (bnc#1133374).
- CVE-2020-12770: Fixed sg_remove_request call in a certain failure cases (bsc#1171420).
- CVE-2020-3702: Fixed a bug which could be triggered with specifically timed and handcrafted traffic and cause internal errors in a WLAN device that lead to improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure. (bnc#1191193)
- CVE-2021-22543: Fixed improper handling of VM_IO<pipe>VM_PFNMAP vmas in KVM, which could bypass RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allowed users with the ability to start and control a VM to read/write random pages of memory and can result in local privilege escalation (bsc#1186482).
- CVE-2021-33033: Fixed a use-after-free in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.78.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.78.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.78.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.78.1", rls:"SLES15.0"))) {
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
