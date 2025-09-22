# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3961.1");
  script_cve_id("CVE-2017-16533", "CVE-2017-18224", "CVE-2018-10902", "CVE-2018-10938", "CVE-2018-10940", "CVE-2018-1128", "CVE-2018-1129", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-13095", "CVE-2018-14613", "CVE-2018-14617", "CVE-2018-14633", "CVE-2018-15572", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-18386", "CVE-2018-18445", "CVE-2018-18710", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-9363");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:33 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 22:07:35 +0000 (Wed, 12 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3961-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3961-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183961-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:3961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-9363: Fixed an integer overflow that could have been used for
 an out of bounds write with no additional execution privileges needed.
 User interaction is not needed for exploitation (bsc#1105292).

CVE-2018-6555: The irda_setsockopt function in net/irda/af_irda.c was
 fixed in drivers/staging/irda/net/af_irda.c that allowed local users to
 cause a denial of service (ias_object use-after-free and system crash)
 or possibly have unspecified other impact via an AF_IRDA socket
 (bsc#1106511).

CVE-2018-6554: Fixed memory leak in the irda_bind function in
 net/irda/af_irda.c and later in drivers/staging/irda/net/af_irda.c that
 allowed local users to cause a denial of service (memory consumption) by
 repeatedly binding an AF_IRDA socket (bsc#1106509).

CVE-2018-18710: An information leak was fixed in cdrom_ioctl_select_disc
 in drivers/cdrom/cdrom.c that could have been used by local attackers to
 read kernel memory because a cast from unsigned long to int interferes
 with bounds checking. This is similar to CVE-2018-10940 and
 CVE-2018-16658 (bsc#1113751).

CVE-2018-18445: Fixed faulty computation of numeric bounds in the BPF
 verifier that now permits out-of-bounds memory accesses because
 adjust_scalar_min_max_vals in kernel/bpf/verifier.c mishandled 32-bit
 right shifts (bsc#1112372).

CVE-2018-17182: The vmacache_flush_all function in mm/vmacache.c was
 fixed that was vulnerable to sequence number overflows. An attacker can
 trigger a use-after-free (and possibly gain privileges) via certain
 thread creation, map, unmap, invalidation, and dereference operations.
 (bsc#1108399).

CVE-2018-16658: An information leak in cdrom_ioctl_drive_status in
 drivers/cdrom/cdrom.c was fixed that could have leed to be used by local
 attackers to read kernel memory because a cast from unsigned long to int
 interferes with bounds checking. This is similar to CVE-2018-10940
 (bsc#1107689).

CVE-2018-15572: The spectre_v2_select_mitigation function in
 arch/x86/kernel/cpu/bugs.c was not always fill RSB upon a context
 switch, which makes it easier for attackers to conduct
 userspace-userspace spectreRSB attacks. (bsc#1102517)

CVE-2018-14633: A security flaw was fixed in the
 chap_server_compute_md5() function in the ISCSI target code in a way an
 authentication request from an ISCSI initiator is processed. An
 unauthenticated remote attacker can cause a stack buffer overflow and
 smash up to 17 bytes of the stack. The attack requires the iSCSI target
 to be enabled on the victim host. Depending on how the target's code was
 built (i.e. depending on a compiler, compile flags and hardware
 architecture) an attack may lead to a system crash and thus to a
 denial-of-service or possibly to a non-authorized access to data
 exported by an iSCSI ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~5.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~5.16.1", rls:"SLES15.0"))) {
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
