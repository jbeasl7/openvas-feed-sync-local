# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122198");
  script_cve_id("CVE-2010-3296", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4648", "CVE-2010-4655", "CVE-2010-4656", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0710", "CVE-2011-0716", "CVE-2011-1478");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:41 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-03 15:16:00 +0000 (Mon, 03 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-0421)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0421");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0421.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-0421 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-71.24.1.el6]
- [fs] Revert '[fs] inotify: stop kernel memory leak on file creation failure' (Eric Paris) [656831 656832] {CVE-2010-4250}

[2.6.32-71.23.1.el6]
- [x86] Revert '[x86] mtrr: Assume SYS_CFG[Tom2ForceMemTypeWB] exists on all future AMD CPUs' (Frank Arnold) [683813 652208]

[2.6.32-71.22.1.el6]
- rebuild

[2.6.32-71.21.1.el6]
- [netdrv] ixgbe: limit VF access to network traffic (Frantisek Hrbata) [684129 678717]
- [netdrv] ixgbe: work around for DDP last buffer size (Frantisek Hrbata) [684129 678717]
- [net] gro: reset dev and skb_iff on skb reuse (Andy Gospodarek) [688311 681970]
- [x86] mtrr: Assume SYS_CFG[Tom2ForceMemTypeWB] exists on all future AMD CPUs (Frank Arnold) [683813 652208]
- [virt] virtio_net: Add schedule check to napi_enable call (Michael S. Tsirkin) [684268 676579]
- [s390x] mm: add devmem_is_allowed() for STRICT_DEVMEM checking (Hendrik Brueckner) [684267 647365]
- [powerpc] Don't use kernel stack with translation off (Steve Best) [684266 628951]
- [powerpc] Initialise paca->kstack before early_setup_secondary (Steve Best) [684266 628951]

[2.6.32-71.20.1.el6]
- [dvb] kernel: av7110 negative array offset (Mauro Carvalho Chehab) [672403 672404] {CVE-2011-0521}
- [fs] sunrpc: Correct a misapplied patch (J. Bruce Fields) [678094 678146] {CVE-2011-0714}
- [netdrv] orinoco: fix TKIP countermeasure behaviour (Stanislaw Gruszka) [667908 667909] {CVE-2010-4648}
- [kernel] /proc/vmcore: speed up access to vmcore file (Neil Horman) [683442 672937]
- [netdrv] cnic: Fix big endian bug (Steve Best) [678484 676640]
- [scsi] fcoe: drop FCoE LOGO in FIP mode (Mike Christie) [683814 668114]
- [s390x] remove task_show_regs (Danny Feng) [677854 677855] {CVE-2011-0710}
- [ib] cm: Bump reference count on cm_id before invoking callback (Doug Ledford) [676190 676191] {CVE-2011-0695}
- [rdma] cm: Fix crash in request handlers (Doug Ledford) [676190 676191] {CVE-2011-0695}
- [net] bridge: Fix mglist corruption that leads to memory corruption (Herbert Xu) [678172 659421] {CVE-2011-0716}
- [netdrv] r8169: use RxFIFO overflow workaround and prevent RxFIFO induced infinite loops (Ivan Vecera) [680080 630810]
- [s390x] kernel: nohz vs cpu hotplug system hang (Hendrik Brueckner) [683815 668470]
- [netdrv] cxgb3/cxgb3_main.c: prevent reading uninitialized stack memory (Doug Ledford) [633156 633157] {CVE-2010-3296}
- [configs] redhat: added CONFIG_SECURITY_DMESG_RESTRICT option (Frantisek Hrbata) [683822 653245]
- [kernel] restrict unprivileged access to kernel syslog (Frantisek Hrbata) [683822 653245]
- [fs] cifs: allow matching of tcp sessions in CifsNew state (Jeff Layton) [683812 629085]
- [fs] cifs: fix potential double put of TCP session reference (Jeff Layton) [683812 629085]
- [fs] cifs: prevent possible memory corruption in cifs_demultiplex_thread (Jeff Layton) [683812 629085]
- [fs] cifs: eliminate some more premature cifsd exits (Jeff Layton) [683812 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.24.1.el6", rls:"OracleLinux6"))) {
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
