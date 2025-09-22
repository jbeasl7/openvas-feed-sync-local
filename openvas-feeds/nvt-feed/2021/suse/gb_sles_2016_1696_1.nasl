# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1696.1");
  script_cve_id("CVE-2014-9717", "CVE-2016-1583", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2188", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3140", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4569");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-04 17:43:50 +0000 (Wed, 04 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1696-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1696-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161696-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/676471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983143");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002139.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:1696-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.59 to receive various security and bugfixes.

Main feature additions:
- Improved support for Clustered File System (CephFS, fate#318586).
- Addition of kGraft patches now produces logging messages to simplify auditing (fate#317827).

The following security bugs were fixed:
- CVE-2016-1583: Prevent the usage of mmap when the lower file system does not allow it. This could have lead to local privilege escalation when ecryptfs-utils was installed and /sbin/mount.ecryptfs_private was setuid (bsc#983143).
- CVE-2014-9717: fs/namespace.c in the Linux kernel processes MNT_DETACH umount2 system calls without verifying that the MNT_LOCKED flag is unset, which allowed local users to bypass intended access restrictions and navigate to filesystem locations beneath a mount by calling umount2 within a user namespace (bnc#928547).
- CVE-2016-2185: The ati_remote2_probe function in drivers/input/misc/ati_remote2.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#971124).
- CVE-2016-2186: The powermate_probe function in drivers/input/misc/powermate.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#970958).
- CVE-2016-2188: The iowarrior_probe function in drivers/usb/misc/iowarrior.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#970956).
- CVE-2016-2847: fs/pipe.c in the Linux kernel did not limit the amount of unread data in pipes, which allowed local users to cause a denial of service (memory consumption) by creating many pipes with non-default sizes (bsc#970948).
- CVE-2016-3134: The netfilter subsystem in the Linux kernel did not validate certain offset fields, which allowed local users to gain privileges or cause a denial of service (heap memory corruption) via an IPT_SO_SET_REPLACE setsockopt call (bnc#971126 971793).
- CVE-2016-3136: The mct_u232_msr_to_state function in drivers/usb/serial/mct_u232.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted USB device without two interrupt-in endpoint descriptors (bnc#970955).
- CVE-2016-3137: drivers/usb/serial/cypress_m8.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a USB device without both an interrupt-in and an interrupt-out endpoint descriptor, related to the cypress_generic_port_probe and cypress_open functions (bnc#970970).
- CVE-2016-3138: The acm_probe ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.59~60.41.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.59~60.41.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.59~60.41.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.59~60.41.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.59~60.41.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.59~60.41.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.59~60.41.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.59~60.41.2", rls:"SLES12.0SP1"))) {
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
