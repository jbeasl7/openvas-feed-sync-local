# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123731");
  script_cve_id("CVE-2012-4398", "CVE-2012-4461", "CVE-2012-4530", "CVE-2013-0190", "CVE-2013-0216", "CVE-2013-0217", "CVE-2013-0231");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:48 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-2503)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2503");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2503.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2013-2503 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-300.28.1]
- kmod: make __request_module() killable (Oleg Nesterov) [Orabug: 16286305]
 {CVE-2012-4398}
- kmod: introduce call_modprobe() helper (Oleg Nesterov) [Orabug: 16286305]
 {CVE-2012-4398}
- usermodehelper: implement UMH_KILLABLE (Oleg Nesterov) [Orabug: 16286305]
 {CVE-2012-4398}
- usermodehelper: introduce umh_complete(sub_info) (Oleg Nesterov) [Orabug:
 16286305] {CVE-2012-4398}
- KVM: x86: invalid opcode oops on SET_SREGS with OSXSAVE bit set
 (CVE-2012-4461) (Jerry Snitselaar) [Orabug: 16286290] {CVE-2012-4461}
- exec: do not leave bprm->interp on stack (Kees Cook) [Orabug: 16286267]
 {CVE-2012-4530}
- exec: use -ELOOP for max recursion depth (Kees Cook) [Orabug: 16286267]
 {CVE-2012-4530}

[2.6.39-300.27.1]
- xen-pciback: rate limit error messages from xen_pcibk_enable_msi{,x}() (Jan
 Beulich) [Orabug: 16243736] {CVE-2013-0231}
- Xen: Fix stack corruption in xen_failsafe_callback for 32bit PVOPS guests.
 (Frediano Ziglio) [Orabug: 16274171] {CVE-2013-0190}
- netback: correct netbk_tx_err to handle wrap around. (Ian Campbell) [Orabug:
 16243309]
- xen/netback: free already allocated memory on failure in
 xen_netbk_get_requests (Ian Campbell) [Orabug: 16243309]
- xen/netback: don't leak pages on failure in xen_netbk_tx_check_gop. (Ian
 Campbell) [Orabug: 16243309]
- xen/netback: shutdown the ring if it contains garbage. (Ian Campbell)
 [Orabug: 16243309]
- ixgbevf fix typo in Makefile (Maxim Uvarov) [Orabug: 16179639 16168292]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~300.28.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~300.28.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~300.28.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~300.28.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~300.28.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~300.28.1.el5uek", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~300.28.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~300.28.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~300.28.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~300.28.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~300.28.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~300.28.1.el6uek", rls:"OracleLinux6"))) {
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
