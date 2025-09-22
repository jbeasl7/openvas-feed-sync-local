# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123629");
  script_cve_id("CVE-2012-4542");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:29 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-2523)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2523");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2523.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2013-2523 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-400.23.1]
- Parallel mtrr init between cpus (Zhenzhong Duan) [Orabug: 16777774]
- Merge tag 'v2.6.39-400.21.1.16748891' of git://ca-git.us.oracle.com/linux-uek-2.6.39-ofed into uek-2.6.39-400 (Maxim Uvarov) [Orabug: 16748891]
- xen-blkfront: use a different scatterlist for each request (Roger Pau Monne)
- Fix EN driver to work with newer FWs based on latest mlx4_core (Yuval Shaia) [Orabug: 16748891]

[2.6.39-400.22.1]
- block: default SCSI command filter does not accommodate commands overlap across device classes (Jamie Iles) [Orabug: 16387137] {CVE-2012-4542}
- Merge tag 'v2.6.39-400.21.1#bug16684527' of git://ca-git.us.oracle.com/linux-joejin-public into uek-2.6.39-400_errata (Maxim Uvarov) [Orabug: 16684527]
- KVM: x86: Convert MSR_KVM_SYSTEM_TIME to use gfn_to_hva_cache functions (CVE-2013-1797) (Andy Honig) [Orabug: 16711660] {CVE-2013-1797}
- Bluetooth: Fix incorrect strncpy() in hidp_setup_hid() (Anderson Lizardo) [Orabug: 16711065] {CVE-2013-0349}
- USB: io_ti: Fix NULL dereference in chase_port() (Wolfgang Frisch) [Orabug: 16425358] {CVE-2013-1774}
- keys: fix race with concurrent install_user_keyrings() (David Howells) [Orabug: 16493354] {CVE-2013-1792}
- KVM: Fix bounds checking in ioapic indirect register reads (CVE-2013-1798) (Andy Honig) [Orabug: 16710951] {CVE-2013-1798}
- KVM: x86: fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME (CVE-2013-1796) (Andy Honig) [Orabug: 16710806] {CVE-2013-1796}
- tmpfs: fix use-after-free of mempolicy object (Greg Thelen) [Orabug: 16515833] {CVE-2013-1767}
- procfs: do not confuse jiffies with cputime64_t (Andreas Schwab) [Orabug: 16673925]
- procfs: do not overflow get_{idle,iowait}_time for nohz (Michal Hocko) [Orabug: 16673925]
- xen/evtchn: Handle VIRQ_TIMER before any other hardirq in event loop. (Keir Fraser) [Orabug: 16093126]
- Fix device removal NULL pointer dereference (Joe Jin) [Orabug: 16684527]
- put stricter guards on queue dead checks (James Bottomley) [Orabug: 16684527]");

  script_tag(name:"affected", value:"'kernel-uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.23.1.el6uek", rls:"OracleLinux6"))) {
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
