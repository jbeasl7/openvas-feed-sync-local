# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0437.1");
  script_cve_id("CVE-2015-1142857", "CVE-2017-13215", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17806", "CVE-2017-18079", "CVE-2017-5715", "CVE-2018-1000004");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-15 18:24:11 +0000 (Thu, 15 Feb 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0437-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0437-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180437-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951638");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2018-February/007939.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0437-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 GA LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-5715: Systems with microprocessors utilizing speculative
 execution and indirect branch prediction may allow unauthorized disclosure
 of information to an attacker with local user access via a side-channel
 analysis (bnc#1068032).

 The previous fix using CPU Microcode has been complemented by building
 the Linux Kernel with return trampolines aka 'retpolines'.

- CVE-2017-18079: drivers/input/serio/i8042.c allowed attackers to cause a
 denial of service (NULL pointer dereference and system crash) or possibly have
 unspecified other impact because the port->exists value can change after it is
 validated (bnc#1077922)
- CVE-2015-1142857: Prevent guests from sending ethernet flow control pause
 frames via the PF (bnc#1077355)
- CVE-2017-17741: KVM allowed attackers to obtain potentially sensitive
 information from kernel memory, aka a write_mmio stack-based out-of-bounds read
 (bnc#1073311)
- CVE-2017-13215: Prevent elevation of privilege (bnc#1075908)
- CVE-2018-1000004: Prevent race condition in the sound system, this could have
 lead a deadlock and denial of service condition (bnc#1076017)
- CVE-2017-17806: The HMAC implementation did not validate that the underlying
 cryptographic hash algorithm is unkeyed, allowing a local attacker able to use
 the AF_ALG-based hash interface (CONFIG_CRYPTO_USER_API_HASH) and the SHA-3
 hash algorithm (CONFIG_CRYPTO_SHA3) to cause a kernel stack buffer overflow by
 executing a crafted sequence of system calls that encounter a missing SHA-3
 initialization (bnc#1073874)
- CVE-2017-17805: The Salsa20 encryption algorithm did not correctly handle
 zero-length inputs, allowing a local attacker able to use the AF_ALG-based
 skcipher interface (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of
 service (uninitialized-memory free and kernel crash) or have unspecified other
 impact by executing a crafted sequence of system calls that use the
 blkcipher_walk API. Both the generic implementation (crypto/salsa20_generic.c)
 and x86 implementation (arch/x86/crypto/salsa20_glue.c) of Salsa20 were
 vulnerable (bnc#1073792)

The following non-security bugs were fixed:

- bcache allocator: send discards with correct size (bsc#1047626).
- bcache.txt: standardize document format (bsc#1076110).
- bcache: Abstract out stuff needed for sorting (bsc#1076110).
- bcache: Add a cond_resched() call to gc (bsc#1076110).
- bcache: Add a real GC_MARK_RECLAIMABLE (bsc#1076110).
- bcache: Add bch_bkey_equal_header() (bsc#1076110).
- bcache: Add bch_btree_keys_u64s_remaining() (bsc#1076110).
- bcache: Add bch_keylist_init_single() (bsc#1047626).
- bcache: Add btree_insert_node() (bnc#951638).
- bcache: Add btree_map() functions (bsc#1047626).
- bcache: Add btree_node_write_sync() (bsc#1076110).
- bcache: Add ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.61~52.119.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_119-default", rpm:"kgraft-patch-3_12_61-52_119-default~1~1.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_119-xen", rpm:"kgraft-patch-3_12_61-52_119-xen~1~1.7.1", rls:"SLES12.0"))) {
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
