# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0168.1");
  script_cve_id("CVE-2015-7550", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-18 17:31:24 +0000 (Mon, 18 Apr 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0168-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0168-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160168-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/758040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960300");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-January/001810.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:0168-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to receive various security and bugfixes.

Following security bugs were fixed:
- CVE-2015-7550: A local user could have triggered a race between read and revoke in keyctl (bnc#958951).
- CVE-2015-8539: A negatively instantiated user key could have been used by a local user to leverage privileges (bnc#958463).
- CVE-2015-8543: The networking implementation in the Linux kernel did not validate protocol identifiers for certain protocol families, which allowed local users to cause a denial of service (NULL function pointer dereference and system crash) or possibly gain privileges by leveraging CLONE_NEWUSER support to execute a crafted SOCK_RAW application (bnc#958886).
- CVE-2015-8550: Compiler optimizations in the XEN PV backend drivers could have lead to double fetch vulnerabilities, causing denial of service or arbitrary code execution (depending on the configuration) (bsc#957988).
- CVE-2015-8551, CVE-2015-8552: xen/pciback: For XEN_PCI_OP_disable_msi[<pipe>x] only disable if device has MSI(X) enabled (bsc#957990).
- CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect functions in drivers/net/ppp/pptp.c in the Linux kernel did not verify an address length, which allowed local users to obtain sensitive information from kernel memory and bypass the KASLR protection mechanism via a crafted application (bnc#959190).
- CVE-2015-8575: Validate socket address length in sco_sock_bind() to prevent information leak (bsc#959399).

The following non-security bugs were fixed:
- ACPICA: Correctly cleanup after a ACPI table load failure (bnc#937261).
- ALSA: hda - Fix noise problems on Thinkpad T440s (boo#958504).
- Input: aiptek - fix crash on detecting device without endpoints (bnc#956708).
- Re-add copy_page_vector_to_user()
- Refresh patches.xen/xen3-patch-3.12.46-47 (bsc#959705).
- Refresh patches.xen/xen3-patch-3.9 (bsc#951155).
- Update patches.suse/btrfs-8361-Btrfs-keep-dropped-roots-in-cache-until-transaction-.patch (bnc#935087, bnc#945649, bnc#951615).
- bcache: Add btree_insert_node() (bnc#951638).
- bcache: Add explicit keylist arg to btree_insert() (bnc#951638).
- bcache: Clean up keylist code (bnc#951638).
- bcache: Convert btree_insert_check_key() to btree_insert_node() (bnc#951638).
- bcache: Convert bucket_wait to wait_queue_head_t (bnc#951638).
- bcache: Convert try_wait to wait_queue_head_t (bnc#951638).
- bcache: Explicitly track btree node's parent (bnc#951638).
- bcache: Fix a bug when detaching (bsc#951638).
- bcache: Fix a lockdep splat in an error path (bnc#951638).
- bcache: Fix a shutdown bug (bsc#951638).
- bcache: Fix more early shutdown bugs (bsc#951638).
- bcache: Fix sysfs splat on shutdown with flash only devs (bsc#951638).
- bcache: Insert multiple keys at a time (bnc#951638).
- bcache: Refactor journalling flow control (bnc#951638).
- bcache: Refactor request_write() (bnc#951638).
- bcache: Use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.51~52.34.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.51~52.34.1", rls:"SLES12.0"))) {
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
