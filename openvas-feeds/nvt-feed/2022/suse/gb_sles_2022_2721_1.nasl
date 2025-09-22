# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2721.1");
  script_cve_id("CVE-2020-15393", "CVE-2020-36557", "CVE-2020-36558", "CVE-2021-33655", "CVE-2021-33656", "CVE-2021-39713", "CVE-2022-1462", "CVE-2022-20166", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-10 04:21:08 +0000 (Wed, 10 Aug 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 20:22:04 +0000 (Tue, 18 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2721-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222721-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201940");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-August/011828.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2022-36946: Fixed an incorrect packet trucation operation which could lead to denial of service (bnc#1201940).
- CVE-2022-20166: Fixed several possible memory safety issues due to unsafe operations (bsc#1200598).
- CVE-2020-15393: Fixed a memory leak in the usbtest driver which could lead to denial of service (bnc#1173514).
- CVE-2020-36558: Fixed a race condition involving VT_RESIZEX which could lead to a NULL pointer dereference and general protection fault (bnc#1200910).
- CVE-2020-36557: Fixed a race condition between the VT_DISALLOCATE ioctl and closing/opening of TTYs could lead to a use-after-free (bnc#1201429).
- CVE-2021-33656: Fixed memory out of bounds write related to ioctl cmd PIO_FONT (bnc#1201636).
- CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO (bnc#1201635).
- CVE-2022-1462: Fixed an out-of-bounds read flaw in the TTY subsystem (bnc#1198829).
- CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742: Fixed multiple potential data leaks with Block and Network devices when using untrusted backends (bsc#1200762).
- CVE-2022-2318: Fixed a use-after-free vulnerability in the timer handler in Rose subsystem that allowed unprivileged attackers to crash the system (bsc#1201251).
- CVE-2021-39713: Fixed a race condition in the network scheduling subsystem which could lead to a use-after-free (bnc#1196973).

The following non-security bugs were fixed:

- kvm: emulate: Do not adjust size of fastop and setcc subroutines (bsc#1201930).
- kvm: emulate: Fix SETcc emulation function offsets with SLS (bsc#1201930).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.181.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.181.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.181.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.181.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.181.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.181.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.181.1", rls:"SLES12.0SP2"))) {
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
