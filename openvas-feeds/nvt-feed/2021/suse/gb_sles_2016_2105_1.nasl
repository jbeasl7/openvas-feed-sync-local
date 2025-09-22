# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2105.1");
  script_cve_id("CVE-2014-9904", "CVE-2015-7833", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8845", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-3672", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4805", "CVE-2016-4997", "CVE-2016-5244", "CVE-2016-5828", "CVE-2016-5829");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-27 15:19:49 +0000 (Mon, 27 Jun 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2105-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162105-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990058");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002218.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.62 to receive various security and bugfixes.

The following security bugs were fixed:
- CVE-2014-9904: The snd_compress_check_input function in sound/core/compress_offload.c in the ALSA subsystem in the Linux kernel did not properly check for an integer overflow, which allowed local users to cause a denial of service (insufficient memory allocation) or possibly have unspecified other impact via a crafted SNDRV_COMPRESS_SET_PARAMS ioctl call (bnc#986811).
- CVE-2015-7833: The usbvision driver in the Linux kernel allowed physically proximate attackers to cause a denial of service (panic) via a nonzero bInterfaceNumber value in a USB device descriptor (bnc#950998).
- CVE-2015-8551: The PCI backend driver in Xen, when running on an x86 system and using Linux as the driver domain, allowed local guest administrators to hit BUG conditions and cause a denial of service (NULL pointer dereference and host OS crash) by leveraging a system with access to a passed-through MSI or MSI-X capable physical PCI device and a crafted sequence of XEN_PCI_OP_* operations, aka 'Linux pciback missing sanity checks (bnc#957990).
- CVE-2015-8552: The PCI backend driver in Xen, when running on an x86 system and using Linux as the driver domain, allowed local guest administrators to generate a continuous stream of WARN messages and cause a denial of service (disk consumption) by leveraging a system with access to a passed-through MSI or MSI-X capable physical PCI device and XEN_PCI_OP_enable_msi operations, aka 'Linux pciback missing sanity checks (bnc#957990).
- CVE-2015-8845: The tm_reclaim_thread function in arch/powerpc/kernel/process.c in the Linux kernel on powerpc platforms did not ensure that TM suspend mode exists before proceeding with a tm_reclaim call, which allowed local users to cause a denial of service (TM Bad Thing exception and panic) via a crafted application (bnc#975533).
- CVE-2016-0758: Integer overflow in lib/asn1_decoder.c in the Linux kernel allowed local users to gain privileges via crafted ASN.1 data (bnc#979867).
- CVE-2016-1583: The ecryptfs_privileged_open function in fs/ecryptfs/kthread.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (stack memory consumption) via vectors involving crafted mmap calls for /proc pathnames, leading to recursive pagefault handling (bsc#983143).
- CVE-2016-2053: The asn1_ber_decoder function in lib/asn1_decoder.c in the Linux kernel allowed attackers to cause a denial of service (panic) via an ASN.1 BER file that lacks a public key, leading to mishandling by the public_key_verify_signature function in crypto/asymmetric_keys/public_key.c (bnc#963762).
- CVE-2016-3672: The arch_pick_mmap_layout function in arch/x86/mm/mmap.c in the Linux kernel did not properly randomize the legacy base address, which made it easier for local users to defeat ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.62~60.62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.62~60.62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.62~60.62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.62~60.62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.62~60.62.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.62~60.62.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.62~60.62.1", rls:"SLES12.0SP1"))) {
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
