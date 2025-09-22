# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2723.1");
  script_cve_id("CVE-2020-36557", "CVE-2020-36558", "CVE-2021-26341", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1462", "CVE-2022-20166", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-10 04:21:08 +0000 (Wed, 10 Aug 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 13:41:08 +0000 (Thu, 04 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2723-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2723-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222723-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201940");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-August/011830.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2723-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-36557: Fixed race condition between the VT_DISALLOCATE ioctl and closing/opening of ttys that could lead to a use-after-free (bnc#1201429).
- CVE-2020-36558: Fixed race condition involving VT_RESIZEX that could lead to a NULL pointer dereference and general protection fault (bnc#1200910).
- CVE-2021-26341: Some AMD CPUs may transiently execute beyond unconditional direct branches, which may potentially result in data leakage (bsc#1201050).
- CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO (bnc#1201635).
- CVE-2021-33656: Fixed out of bounds write with ioctl PIO_FONT (bnc#1201636).
- CVE-2022-1462: Fixed an out-of-bounds read flaw in the TeleTYpe subsystem (bnc#1198829).
- CVE-2022-20166: Fixed possible out of bounds write due to sprintf unsafety that could cause local escalation of privilege (bnc#1200598).
- CVE-2022-36946: Fixed incorrect packet truncation in nfqnl_mangle() that could lead to remote DoS (bnc#1201940).

The following non-security bugs were fixed:

- Add missing recommends of kernel-install-tools to kernel-source-vanilla (bsc#1200442)
- cifs: On cifs_reconnect, resolve the hostname again (bsc#1201926).
- cifs: Simplify reconnect code when dfs upcall is enabled (bsc#1201926).
- cifs: To match file servers, make sure the server hostname matches (bsc#1201926).
- cifs: fix memory leak of smb3_fs_context_dup::server_hostname (bsc#1201926).
- cifs: fix potential use-after-free in cifs_echo_request() (bsc#1201926).
- cifs: set a minimum of 120s for next dns resolution (bsc#1201926).
- cifs: use the expiry output of dns_query to schedule next resolution (bsc#1201926).
- kernel-binary.spec: Support radio selection for debuginfo. To disable debuginfo on 5.18 kernel a radio selection needs to be switched to a different selection. This requires disabling the currently active option and selecting NONE as debuginfo type.
- kernel-binary.spec: check s390x vmlinux location As a side effect of mainline commit edd4a8667355 ('s390/boot: get rid of startup archive'), vmlinux on s390x moved from 'compressed' subdirectory directly into arch/s390/boot. As the specfile is shared among branches, check both locations and let objcopy use one that exists.
- kvm: emulate: Fix SETcc emulation function offsets with SLS (bsc#1201930).
- kvm: emulate: do not adjust size of fastop and setcc subroutines (bsc#1201930).
- pahole 1.22 required for full BTF features. also recommend pahole for kernel-source to make the kernel buildable with standard config
- rpm/*.spec.in: remove backtick usage
- rpm/constraints.in: skip SLOW_DISK workers for kernel-source
- rpm/kernel-obs-build.spec.in: Also depend on dracut-systemd (bsc#1195775)
- rpm/kernel-obs-build.spec.in: add systemd-initrd and terminfo dracut module (bsc#1195775)
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150000.150.98.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150000.150.98.1", rls:"SLES15.0"))) {
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
