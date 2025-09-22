# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122384");
  script_cve_id("CVE-2009-4308", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0008", "CVE-2010-0415", "CVE-2010-0437");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:57 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0147)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0147");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0147.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-164.15.1.0.1.el5, oracleasm-2.6.18-164.15.1.0.1.el5' package(s) announced via the ELSA-2010-0147 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-164.15.1.0.1.el5]
- [xen] check to see if hypervisor supports memory reservation change
 (Chuck Anderson) [orabug 7556514]
- Add entropy support to igb ( John Sobecki) [orabug 7607479]
- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043]
 [bz 7258]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [nfsd] fix failure of file creation from hpux client (Wen gang Wang)
 [orabug 7579314]
- FP register state is corrupted during the handling a SIGSEGV (Chuck Anderson)
 [orabug 7708133]
- [x86_64] PCI space below 4GB forces mem remap above 1TB (Larry Woodman)
 [523522]
- [cpufreq] P-state limit: limit can never be increased (Stanislaw Gruszka)
 [489566]
- [rds] patch rds to 4.0-ora-1.4.2-10 (Andy Grover, Tina Yang)
 [orabug 9168046] [RHBZ 546374]

[2.6.18-164.15.1.el5]
- [net] sctp: backport cleanups for ootb handling V2 (Neil Horman) [555666 555667] {CVE-2010-0008}
- Reverting: [net] sctp: backport cleanups for ootb handling (Neil Horman) [555666 555667] {CVE-2010-0008}

[2.6.18-164.14.1.el5]
- [fs] ext4: Avoid null pointer dereference when decoding EROFS w/o a journal (Jiri Pirko) [547256 547257] {CVE-2009-4308}
- [net] sctp: backport cleanups for ootb handling (Neil Horman) [555666 555667] {CVE-2010-0008}
- [mm] fix sys_move_pages infoleak (Eugene Teo) [562589 562590] {CVE-2010-0415}
- [x86_64] wire up compat sched_rr_get_interval (Danny Feng) [557684 557092]
- [net] netfilter: enforce CAP_NET_ADMIN in ebtables (Danny Feng) [555242 555243] {CVE-2010-0007}
- [misc] fix kernel info leak with print-fatal-signals=1 (Danny Feng) [554583 554584] {CVE-2010-0003}
- [net] ipv6: fix OOPS in ip6_dst_lookup_tail (Thomas Graf) [559238 552354]
- [kvm] pvclock on i386 suffers from double registering (Glauber Costa) [561454 557095]
- [pci] VF can't be enabled in dom0 (Don Dutile) [560665 547980]
- [kvm] kvmclock won't restore properly after resume (Glauber Costa) [560640 539521]
- [mm] prevent performance hit for 32-bit apps on x86_64 (Larry Woodman) [562746 544448]
- [fs] fix possible inode corruption on unlock (Eric Sandeen) [564281 545612]
- [gfs2] careful unlinking inodes (Steven Whitehouse ) [564288 519049]
- [gfs2] gfs2_delete_inode failing on RO filesystem (Abhijith Das ) [564290 501359]

[2.6.18-164.13.1.el5]
- [net] e1000e: fix broken wol (Andy Gospodarek) [559335 557974]
- [net] gro: fix illegal merging of trailer trash (Herbert Xu) [561417 537876]
- [xen] hook sched rebalance logic to opt_hardvirt (Christopher Lalancette ) [562777 529271]
- [xen] crank the correct stat in the scheduler (Christopher Lalancette ) [562777 529271]
- [xen] whitespace fixups in xen scheduler (Christopher Lalancette ) [562777 529271]
- [scsi] cciss: ignore stale commands after reboot (Tomas Henzl ) [562772 525440]
- [scsi] cciss: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-164.15.1.0.1.el5, oracleasm-2.6.18-164.15.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.15.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.15.1.0.1.el5", rpm:"ocfs2-2.6.18-164.15.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.15.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-164.15.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.15.1.0.1.el5debug", rpm:"ocfs2-2.6.18-164.15.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.15.1.0.1.el5xen", rpm:"ocfs2-2.6.18-164.15.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.15.1.0.1.el5", rpm:"oracleasm-2.6.18-164.15.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.15.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-164.15.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.15.1.0.1.el5debug", rpm:"oracleasm-2.6.18-164.15.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.15.1.0.1.el5xen", rpm:"oracleasm-2.6.18-164.15.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
