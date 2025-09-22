# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1672.1");
  script_cve_id("CVE-2015-7566", "CVE-2015-8816", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2187", "CVE-2016-2188", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-5244");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-24 14:13:11 +0000 (Tue, 24 May 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1672-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1672-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161672-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/676471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/965923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984107");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-June/002135.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:1672-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

Notable changes in this kernel:
- It is now possible to mount a NFS export on the exporting host directly.

The following security bugs were fixed:
- CVE-2016-5244: A kernel information leak in rds_inc_info_copy was fixed that could leak kernel stack memory to userspace (bsc#983213).
- CVE-2016-1583: Prevent the usage of mmap when the lower file system does not allow it. This could have lead to local privilege escalation when ecryptfs-utils was installed and /sbin/mount.ecryptfs_private was setuid (bsc#983143).
- CVE-2016-4913: The get_rock_ridge_filename function in fs/isofs/rock.c in the Linux kernel mishandles NM (aka alternate name) entries containing \0 characters, which allowed local users to obtain sensitive information from kernel memory or possibly have unspecified other impact via a crafted isofs filesystem (bnc#980725).
- CVE-2016-4580: The x25_negotiate_facilities function in net/x25/x25_facilities.c in the Linux kernel did not properly initialize a certain data structure, which allowed attackers to obtain sensitive information from kernel stack memory via an X.25 Call Request (bnc#981267).
- CVE-2016-4805: Use-after-free vulnerability in drivers/net/ppp/ppp_generic.c in the Linux kernel allowed local users to cause a denial of service (memory corruption and system crash, or spinlock) or possibly have unspecified other impact by removing a network namespace, related to the ppp_register_net_channel and ppp_unregister_channel functions (bnc#980371).
- CVE-2016-0758: Tags with indefinite length could have corrupted pointers in asn1_find_indefinite_length (bsc#979867).
- CVE-2016-2187: The gtco_probe function in drivers/input/tablet/gtco.c in the Linux kernel allowed physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor (bnc#971944).
- CVE-2016-4482: The proc_connectinfo function in drivers/usb/core/devio.c in the Linux kernel did not initialize a certain data structure, which allowed local users to obtain sensitive information from kernel stack memory via a crafted USBDEVFS_CONNECTINFO ioctl call (bnc#978401).
- CVE-2016-2053: The asn1_ber_decoder function in lib/asn1_decoder.c in the Linux kernel allowed attackers to cause a denial of service (panic) via an ASN.1 BER file that lacks a public key, leading to mishandling by the public_key_verify_signature function in crypto/asymmetric_keys/public_key.c (bnc#963762).
- CVE-2016-4565: The InfiniBand (aka IB) stack in the Linux kernel incorrectly relies on the write system call, which allowed local users to cause a denial of service (kernel memory write operation) or possibly have unspecified other impact via a uAPI interface (bnc#979548).
- CVE-2016-4485: The llc_cmsg_rcv function in net/llc/af_llc.c in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~77.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~77.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~77.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~77.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~77.1", rls:"SLES11.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~77.1", rls:"SLES11.0SP4"))) {
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
