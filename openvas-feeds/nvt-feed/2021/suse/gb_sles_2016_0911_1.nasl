# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0911.1");
  script_cve_id("CVE-2013-7446", "CVE-2015-7515", "CVE-2015-7550", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-02 17:13:23 +0000 (Mon, 02 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0911-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0911-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160911-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/758040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969307");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-March/001972.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:0911-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

Following feature was added to kernel-xen:
- A improved XEN blkfront module was added, which allows more I/O bandwidth. (FATE#320200)
 It is called xen-blkfront in PV, and xen-vbd-upstream in HVM mode.

The following security bugs were fixed:
- CVE-2013-7446: Use-after-free vulnerability in net/unix/af_unix.c in
 the Linux kernel allowed local users to bypass intended AF_UNIX socket
 permissions or cause a denial of service (panic) via crafted epoll_ctl
 calls (bnc#955654).
- CVE-2015-7515: An out of bounds memory access in the aiptek USB
 driver could be used by physical local attackers to crash the kernel
 (bnc#956708).
- CVE-2015-7550: The keyctl_read_key function in security/keys/keyctl.c
 in the Linux kernel did not properly use a semaphore, which allowed
 local users to cause a denial of service (NULL pointer dereference and
 system crash) or possibly have unspecified other impact via a crafted
 application that leverages a race condition between keyctl_revoke and
 keyctl_read calls (bnc#958951).
- CVE-2015-8539: The KEYS subsystem in the Linux kernel allowed
 local users to gain privileges or cause a denial of service (BUG)
 via crafted keyctl commands that negatively instantiate a key, related
 to security/keys/encrypted-keys/encrypted.c, security/keys/trusted.c,
 and security/keys/user_defined.c (bnc#958463).
- CVE-2015-8543: The networking implementation in the Linux kernel
 did not validate protocol identifiers for certain protocol families,
 which allowed local users to cause a denial of service (NULL function
 pointer dereference and system crash) or possibly gain privileges by
 leveraging CLONE_NEWUSER support to execute a crafted SOCK_RAW application
 (bnc#958886).
- CVE-2015-8550: Compiler optimizations in the XEN PV backend drivers
 could have lead to double fetch vulnerabilities, causing denial of service
 or arbitrary code execution (depending on the configuration) (bsc#957988).
- CVE-2015-8551, CVE-2015-8552: xen/pciback: For
 XEN_PCI_OP_disable_msi[<pipe>x] only disable if device has MSI(X) enabled
 (bsc#957990).
- CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect functions in
 drivers/net/ppp/pptp.c in the Linux kernel did not verify an address
 length, which allowed local users to obtain sensitive information from
 kernel memory and bypass the KASLR protection mechanism via a crafted
 application (bnc#959190).
- CVE-2015-8575: The sco_sock_bind function in net/bluetooth/sco.c in the
 Linux kernel did not verify an address length, which allowed local users
 to obtain sensitive information from kernel memory and bypass the KASLR
 protection mechanism via a crafted application (bnc#959190 bnc#959399).
- CVE-2015-8767: net/sctp/sm_sideeffect.c in the Linux kernel did not
 properly manage the relationship between a lock and a socket, which
 allowed local ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~71.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~71.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~71.1", rls:"SLES11.0SP4"))) {
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
