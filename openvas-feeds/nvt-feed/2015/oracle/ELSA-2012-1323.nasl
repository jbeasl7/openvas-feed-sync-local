# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123808");
  script_cve_id("CVE-2012-2319", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3510");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:50 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-1323)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1323");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1323.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.16.1.el5, oracleasm-2.6.18-308.16.1.el5' package(s) announced via the ELSA-2012-1323 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-308.16.1.el5]
- Revert: [fs] nfsd4: Remove check for a 32-bit cookie in nfsd4_readdir() (Eric Sandeen) [847943 784191]
- Revert: [fs] add new FMODE flags: FMODE_32bithash and FMODE_64bithash (Eric Sandeen) [847943 784191]
- Revert: [fs] nfsd: rename int access to int may_flags in nfsd_open() (Eric Sandeen) [847943 784191]
- Revert: [fs] nfsd: vfs_llseek() with 32 or 64 bit offsets (hashes) (Eric Sandeen) [847943 784191]
- Revert: [fs] vfs: add generic_file_llseek_size (Eric Sandeen) [847943 784191]
- Revert: [s390/ppc64] add is_compat_task() for s390 and ppc64 (Eric Sandeen) [847943 784191]
- Revert: [fs] ext3: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]
- Revert: [fs] ext4: improve llseek error handling for large seek offsets (Eric Sandeen) [847943 784191]
- Revert: [fs] ext4: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]
- Revert: [fs] vfs: allow custom EOF in generic_file_llseek code (Eric Sandeen) [847943 784191]
- Revert: [fs] ext4: use core vfs llseek code for dir seeks (Eric Sandeen) [847943 784191]
- Revert: [fs] ext3: pass custom EOF to generic_file_llseek_size() (Eric Sandeen) [847943 784191]

[2.6.18-308.15.1.el5]
- [net] sfc: Fix max no of TSO segments and min TX queue size (Michal Schmidt) [845554 845555] {CVE-2012-3412}
- [kernel] xacct_add_tsk: fix pure theoretical ->mm use-after-free (Nikola Pajkovsky) [849723 849725] {CVE-2012-3510}
- [fs] hfsplus: Buffer overflow in the HFS plus filesystem (Jacob Tanenbaum) [820255 820256] {CVE-2012-2319}
- [net] netfilter: add dscp netfilter match (Thomas Graf) [847327 842029]
- [net] rds: set correct msg_namelen (Weiping Pan) [822727 822728] {CVE-2012-3430}
- [misc] ERESTARTNOINTR seen from fork call in userspace (Oleg Nesterov) [847359 693822]
- [fs] quota: manage reserved space when quota is not active (Eric Sandeen) [847326 818087]
- [fs] quota: Fix warning if delayed write before quota is enabled (Eric Sandeen) [847326 818087]
- [fs] ext3: pass custom EOF to generic_file_llseek_size() (Eric Sandeen) [847943 784191]
- [fs] ext4: use core vfs llseek code for dir seeks (Eric Sandeen) [847943 784191]
- [fs] vfs: allow custom EOF in generic_file_llseek code (Eric Sandeen) [847943 784191]
- [fs] ext4: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]
- [fs] ext4: improve llseek error handling for large seek offsets (Eric Sandeen) [847943 784191]
- [fs] ext3: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [847943 784191]
- [s390/ppc64] add is_compat_task() for s390 and ppc64 (Eric Sandeen) [847943 784191]
- [fs] vfs: add generic_file_llseek_size (Eric Sandeen) [847943 784191]
- [fs] nfsd: vfs_llseek() with 32 or 64 bit offsets (hashes) (Eric Sandeen) [847943 784191]
- [fs] nfsd: rename int access to int may_flags in nfsd_open() (Eric Sandeen) [847943 784191]
- [fs] ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.16.1.el5, oracleasm-2.6.18-308.16.1.el5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.16.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.el5", rpm:"ocfs2-2.6.18-308.16.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.el5PAE", rpm:"ocfs2-2.6.18-308.16.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.el5debug", rpm:"ocfs2-2.6.18-308.16.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.el5xen", rpm:"ocfs2-2.6.18-308.16.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.el5", rpm:"oracleasm-2.6.18-308.16.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.el5PAE", rpm:"oracleasm-2.6.18-308.16.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.el5debug", rpm:"oracleasm-2.6.18-308.16.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.el5xen", rpm:"oracleasm-2.6.18-308.16.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
