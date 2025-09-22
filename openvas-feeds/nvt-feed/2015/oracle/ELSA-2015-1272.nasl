# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123058");
  script_cve_id("CVE-2014-3184", "CVE-2014-3940", "CVE-2014-4652", "CVE-2014-8133", "CVE-2014-8709", "CVE-2014-9683", "CVE-2015-0239", "CVE-2015-3339");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:49 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-1272)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1272");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1272.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-1272 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-573]
- [security] selinux: don't waste ebitmap space when importing NetLabel categories (Paul Moore) [1130197]
- [x86] Revert Add driver auto probing for x86 features v4 (Prarit Bhargava) [1231280]
- [net] bridge: netfilter: don't call iptables on vlan packets if sysctl is off (Florian Westphal) [1236551]
- [net] ebtables: Allow filtering of hardware accelerated vlan frames (Florian Westphal) [1236551]

[2.6.32-572]
- [fs] Revert fuse: use clear_highpage and KM_USER0 instead of KM_USER1 (Brian Foster) [1229562]

[2.6.32-571]
- [netdrv] bnx2x: Move statistics implementation into semaphores (Michal Schmidt) [1231348]
- [scsi] storvsc: Set the SRB flags correctly when no data transfer is needed (Vitaly Kuznetsov) [1221404]

[2.6.32-570]
- [block] fix ext_dev_lock lockdep report (Jeff Moyer) [1230927]
- [md] Revert md dm: run queue on re-queue (Mike Snitzer) [1232007]
- [firmware] another cxgb4 firmware load fixup (Sai Vemuri) [1189255]
- [char] tty: Don't protect atomic operation with mutex (Aristeu Rozanski) [1184182]
- [edac] i5100 add 6 ranks per channel (Aristeu Rozanski) [1171333]
- [edac] i5100 clean controller to channel terms (Aristeu Rozanski) [1171333]
- [crypto] rng - Remove krng (Herbert Xu) [1226418]
- [crypto] drbg - Add stdrng alias and increase priority (Herbert Xu) [1226418]
- [crypto] seqiv - Move IV seeding into init function (Herbert Xu) [1226418]
- [crypto] eseqiv - Move IV seeding into init function (Herbert Xu) [1226418]
- [crypto] chainiv - Move IV seeding into init function (Herbert Xu) [1226418]

[2.6.32-569]
- [gpu] drm/radeon: fix freeze for laptop with Turks/Thames GPU (Jerome Glisse) [1213297]
- [md] dm: fix casting bug in dm_merge_bvec (Mike Snitzer) [1226453]
- [fs] nfs: Send the size attribute on open(O_TRUNC) (Benjamin Coddington) [1208065]
- [net] inet: fix processing of ICMP frag_needed messages (Sabrina Dubroca) [1210321]
- [net] tcp: double default TSQ output bytes limit (Hannes Frederic Sowa) [1140590]
- [hv] hv_balloon: correctly handle num_pages>INT_MAX case (Vitaly Kuznetsov) [1006234]
- [hv] hv_balloon: correctly handle val.freeram- [hv] hv_balloon: survive ballooning request with num_pages=0 (Vitaly Kuznetsov) [1006234]- [hv] hv_balloon: eliminate jumps in piecewise linear floor function (Vitaly Kuznetsov) [1006234]- [hv] hv_balloon: do not online pages in offline blocks (Vitaly Kuznetsov) [1006234]- [hv] hv_balloon: don't lose memory when onlining order is not natural (Vitaly Kuznetsov) [1006234][2.6.32-568]- [base] reduce boot delay on large memory systems (Seth Jennings) [1221389]- [md] dm: run queue on re-queue (Mike Snitzer) [1225158]- [fs] take i_mutex during prepare_binprm for setid executables (Mateusz Guzik) [1216269] {CVE-2015-3339}- [netdrv] i40e: Make sure to be in VEB mode if SRIOV is enabled at probe (Stefan Assmann) [1206000]- [netdrv] i40e: start up in VEPA mode by default (Stefan Assmann) [1206000]- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.el6", rls:"OracleLinux6"))) {
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
