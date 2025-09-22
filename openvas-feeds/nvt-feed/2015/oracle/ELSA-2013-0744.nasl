# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123637");
  script_cve_id("CVE-2012-6537", "CVE-2012-6546", "CVE-2012-6547", "CVE-2013-0349", "CVE-2013-0913", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1826", "CVE-2013-1827");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:36 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0744)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0744");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0744.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-0744 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-358.6.1]
- [virt] kvm: accept unaligned MSR_KVM_SYSTEM_TIME writes (Petr Matousek) [917020 917021] {CVE-2013-1796}
- [char] tty: hold lock across tty buffer finding and buffer filling (Prarit Bhargava) [928686 901780]
- [net] tcp: fix for zero packets_in_flight was too broad (Thomas Graf) [927309 920794]
- [net] tcp: frto should not set snd_cwnd to 0 (Thomas Graf) [927309 920794]
- [net] tcp: fix an infinite loop in tcp_slow_start() (Thomas Graf) [927309 920794]
- [net] tcp: fix ABC in tcp_slow_start() (Thomas Graf) [927309 920794]
- [netdrv] ehea: avoid accessing a NULL vgrp (Steve Best) [921535 911359]
- [net] sunrpc: Get rid of the redundant xprt->shutdown bit field (J. Bruce Fields) [915579 893584]
- [virt] kvm: do not #GP on unaligned MSR_KVM_SYSTEM_TIME write (Gleb Natapov) [917020 917021] {CVE-2013-1796}
- [drm] i915: bounds check execbuffer relocation count (Nikola Pajkovsky) [920523 920525] {CVE-2013-0913}
- [x86] irq: add quirk for broken interrupt remapping on 55XX chipsets (Neil Horman) [911267 887006]
- [kvm] Convert MSR_KVM_SYSTEM_TIME to use gfn_to_hva_cache functions (Gleb Natapov) [917024 917025] {CVE-2013-1797}
- [kvm] Fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (Gleb Natapov) [917020 917021] {CVE-2013-1796}
- [kvm] Fix bounds checking in ioapic indirect register reads (Gleb Natapov) [917030 917032] {CVE-2013-1798}
- [kvm] x86: release kvmclock page on reset (Gleb Natapov) [917024 917025] {CVE-2013-1797}
- [security] keys: Fix race with concurrent install_user_keyrings() (David Howells) [916681 913258] {CVE-2013-1792}
- [virt] hv_balloon: Make adjustments to the pressure report (Jason Wang) [909156 902232]

[2.6.32-358.5.1]
- [fs] xfs: use maximum schedule timeout when ail is empty (Brian Foster) [921958 883905]
- [net] xfrm_user: fix info leak in copy_to_user_tmpl() (Thomas Graf) [922428 922429] {CVE-2012-6537}
- [net] xfrm_user: fix info leak in copy_to_user_policy() (Thomas Graf) [922428 922429] {CVE-2012-6537}
- [net] xfrm_user: fix info leak in copy_to_user_state() (Thomas Graf) [922428 922429] {CVE-2012-6537}
- [net] xfrm_user: fix info leak in copy_to_user_auth() (Thomas Graf) [922428 922429] {CVE-2012-6537}
- [net] atm: fix info leak in getsockopt(SO_ATMPVC) (Thomas Graf) [922386 922387] {CVE-2012-6546}
- [net] atm: fix info leak via getsockname() (Thomas Graf) [922386 922387] {CVE-2012-6546}
- [fs] nls: improve UTF8 -> UTF16 string conversion routine (Nikola Pajkovsky) [916118 916119] {CVE-2013-1773}
- [fs] fat: Fix stat->f_namelen (Nikola Pajkovsky) [916118 916119] {CVE-2013-1773}
- [netdrv] tun: fix ioctl() based info leaks (Thomas Graf) [922350 922351] {CVE-2012-6547}
- [virt] x86: Add a check to catch Xen emulation of Hyper-V (Andrew Jones) [923204 918239]
- [fs] cifs: fix expand_dfs_referral (Sachin Prabhu) [923098 902492]
- [fs] cifs: factor smb_vol allocation out of cifs_setup_volume_info (Sachin Prabhu) [923098 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.6.1.el6", rls:"OracleLinux6"))) {
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
