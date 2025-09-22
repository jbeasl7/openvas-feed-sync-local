# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122422");
  script_cve_id("CVE-2009-2695", "CVE-2009-2908", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3613");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:01 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 15:44:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2009-1548)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1548");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1548.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-164.6.1.0.1.el5, oracleasm-2.6.18-164.6.1.0.1.el5' package(s) announced via the ELSA-2009-1548 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-164.6.1.0.1.el5]
- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]
- Add entropy support to igb ( John Sobecki) [orabug 7607479]
- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]

[2.6.18-164.6.1.el5]
- [fs] fix pipe null pointer dereference (Jeff Moyer) [530938 530939] {CVE-2009-3547}
- [security] require root for mmap_min_addr (Eric Paris ) [518142 518143] {CVE-2009-2695}
- [net] lvs: adjust sync protocol handling for ipvsadm -2 (Neil Horman ) [528645 524129]
- [xen] allow booting with broken serial hardware (Chris Lalancette ) [524153 518338]

[2.6.18-164.5.1.el5]
- [fs] eCryptfs: prevent lower dentry from going negative (Eric Sandeen ) [527834 527835] {CVE-2009-2908}
- [nfs] v4: reclaimer thread stuck in an infinite loop (Sachin S. Prabhu ) [529162 526888]
- [net] r8169: avoid losing MSI interrupts (Ivan Vecera ) [529366 514589]
- [scsi] st.c: memory use after free after MTSETBLK ioctl (David Jeffery ) [528133 520192]
- [net] r8169: balance pci_map/unmap pair, use hw padding (Ivan Vecera ) [529143 515857] {CVE-2009-3613}

[2.6.18-164.4.1.el5]
- [net] bonding: set primary param via sysfs (Jiri Pirko ) [517971 499884]
- [scsi] fusion: re-enable mpt_msi_enable option (Tomas Henzl ) [526963 520820]
- [net] ipt_recent: sanity check hit count (Amerigo Wang ) [527434 523982]
- [net] ipv4: ip_append_data handle NULL routing table (Jiri Pirko ) [527436 520297]
- [nfs] fix cache invalidation problems in nfs_readdir (Jeff Layton ) [526960 511170]
- [net] tc: fix uninitialized kernel memory leak (Jiri Pirko ) [520994 520863]

[2.6.18-164.3.1.el5]
- [nfs] knfsd: fix NFSv4 O_EXCL creates (Jeff Layton ) [522163 524521] {CVE-2009-3286}");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-164.6.1.0.1.el5, oracleasm-2.6.18-164.6.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.6.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.6.1.0.1.el5", rpm:"ocfs2-2.6.18-164.6.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.6.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-164.6.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.6.1.0.1.el5debug", rpm:"ocfs2-2.6.18-164.6.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.6.1.0.1.el5xen", rpm:"ocfs2-2.6.18-164.6.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.6.1.0.1.el5", rpm:"oracleasm-2.6.18-164.6.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.6.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-164.6.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.6.1.0.1.el5debug", rpm:"oracleasm-2.6.18-164.6.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.6.1.0.1.el5xen", rpm:"oracleasm-2.6.18-164.6.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
