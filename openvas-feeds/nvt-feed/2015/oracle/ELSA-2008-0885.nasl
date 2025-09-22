# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122555");
  script_cve_id("CVE-2007-6417", "CVE-2007-6716", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:54 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 14:50:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2008-0885)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0885");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0885.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-92.1.13.0.1.el5, oracleasm-2.6.18-92.1.13.0.1.el5' package(s) announced via the ELSA-2008-0885 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-92.1.13.0.1.el5]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [orabug 6045759]
- [splice] Fix bad unlock_page() in error case (Jens Axboe) [orabug 6263574]
- [NET] fix netpoll race (Tina Yang) [orabugz 5791]

[2.6.18-92.1.13.el5]
- [md] fix crashes in iterate_rdev (Doug Ledford ) [460128 455471]
- [sound] snd_seq_oss_synth_make_info info leak (Eugene Teo ) [458000 458001] {CVE-2008-3272}
- [ipmi] control BMC device ordering (peterm@redhat.com ) [459071 430157]
- [ia64] fix to check module_free parameter (Masami Hiramatsu ) [460639 457961]
- [misc] NULL pointer dereference in kobject_get_path (Jiri Pirko ) [459776 455460]
- [xen] ia64: SMP-unsafe with XENMEM_add_to_physmap on HVM (Tetsu Yamamoto ) [459780 457137]
- [net] bridge: eliminate delay on carrier up (Herbert Xu ) [458783 453526]
- [fs] dio: lock refcount operations (Jeff Moyer ) [459082 455750]
- [misc] serial: fix break handling for i82571 over LAN (Aristeu Rozanski ) [460509 440018]
- [fs] dio: use kzalloc to zero out struct dio (Jeff Moyer ) [461091 439918]
- [fs] lockd: nlmsvc_lookup_host called with f_sema held (Jeff Layton ) [459083 453094]
- [net] bnx2x: chip reset and port type fixes (Andy Gospodarek ) [441259 442026]

[2.6.18-92.1.12.el5]
- [mm] tmpfs: restore missing clear_highpage (Eugene Teo ) [426082 426083]{CVE-2007-6417}
- [fs] vfs: fix lookup on deleted directory (Eugene Teo ) [457865 457866]{CVE-2008-3275}
- [net] ixgbe: remove device ID for unsupported device (Andy Gospodarek ) [457484 454910]
- [ppc] Event Queue overflow on eHCA adapters (Brad Peters ) [458779 446713]

[2.6.18-92.1.11.el5]
- [mm] xpmem: inhibit page swapping under heavy mem use (George Beshers ) [456946 456574]
- [xen] HV: memory corruption with large number of cpus (Chris Lalancette ) [455768 449945]
- [fs] missing check before setting mount propagation (Eugene Teo ) [454392 454393]
- [openib] small ipoib packet can cause an oops (Doug Ledford ) [447913 445731]
- [misc] fix race in switch_uid and user signal accounting (Vince Worthington ) [456235 441762 440830]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-92.1.13.0.1.el5, oracleasm-2.6.18-92.1.13.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.13.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.13.0.1.el5", rpm:"ocfs2-2.6.18-92.1.13.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.13.0.1.el5PAE", rpm:"ocfs2-2.6.18-92.1.13.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.13.0.1.el5debug", rpm:"ocfs2-2.6.18-92.1.13.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.13.0.1.el5xen", rpm:"ocfs2-2.6.18-92.1.13.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.13.0.1.el5", rpm:"oracleasm-2.6.18-92.1.13.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.13.0.1.el5PAE", rpm:"oracleasm-2.6.18-92.1.13.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.13.0.1.el5debug", rpm:"oracleasm-2.6.18-92.1.13.0.1.el5debug~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.13.0.1.el5xen", rpm:"oracleasm-2.6.18-92.1.13.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
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
