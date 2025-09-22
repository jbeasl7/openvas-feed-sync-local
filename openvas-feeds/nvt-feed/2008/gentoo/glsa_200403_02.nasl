# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54527");
  script_cve_id("CVE-2004-0077");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200403-02 (Kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A critical security vulnerability has been found in recent Linux kernels by
Paul Starzetz of iSEC Security Research which allows for local privilege
escalations.");
  script_tag(name:"solution", value:"Users are encouraged to upgrade to the latest available sources for their
system:

    # emerge sync
    # emerge -pv your-favourite-sources
    # emerge your-favourite-sources
    # # Follow usual procedure for compiling and installing a kernel.
    # # If you use genkernel, run genkernel as you would do normally.

    # # IF YOUR KERNEL IS MARKED as 'remerge required!' THEN
    # # YOU SHOULD UPDATE YOUR KERNEL EVEN IF PORTAGE
    # # REPORTS THAT THE SAME VERSION IS INSTALLED.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=42024");
  script_xref(name:"URL", value:"http://isec.pl/vulnerabilities/isec-0014-mremap-unmap.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200403-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-kernel/aa-sources", unaffected: make_list("ge 2.4.23-r1"), vulnerable: make_list("lt 2.4.23-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/alpha-sources", unaffected: make_list("ge 2.4.21-r4"), vulnerable: make_list("lt 2.4.21-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ck-sources", unaffected: make_list("eq 2.4.24-r1", "ge 2.6.2-r1"), vulnerable: make_list("lt 2.6.2-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/compaq-sources", unaffected: make_list("ge 2.4.9.32.7-r2"), vulnerable: make_list("lt 2.4.9.32.7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/development-sources", unaffected: make_list("ge 2.6.3_rc1"), vulnerable: make_list("lt 2.6.3_rc1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gaming-sources", unaffected: make_list("ge 2.4.20-r8"), vulnerable: make_list("lt 2.4.20-r8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.3_rc1"), vulnerable: make_list("lt 2.6.3_rc1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-sources", unaffected: make_list("eq 2.4.19-r11", "eq 2.4.20-r12", "ge 2.4.22-r7"), vulnerable: make_list("lt 2.4.22-r7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/grsec-sources", unaffected: make_list("ge 2.4.24.1.9.13-r1"), vulnerable: make_list("lt 2.4.24.1.9.13-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r2"), vulnerable: make_list("lt 2.4.25_pre7-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hardened-sources", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-dev-sources", unaffected: make_list("ge 2.6.2_p3-r1"), vulnerable: make_list("lt 2.6.2_p3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/hppa-sources", unaffected: make_list("ge 2.4.24_p0-r1"), vulnerable: make_list("lt 2.4.24_p0-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ia64-sources", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-prepatch-sources", unaffected: make_list("ge 2.4.25_pre6-r1"), vulnerable: make_list("lt 2.4.25_pre6-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mips-sources", unaffected: make_list("ge 2.4.25_rc4"), vulnerable: make_list("lt 2.4.25_rc4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/mm-sources", unaffected: make_list("ge 2.6.3_rc1-r1"), vulnerable: make_list("lt 2.6.3_rc1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/openmosix-sources", unaffected: make_list("ge 2.4.22-r4"), vulnerable: make_list("lt 2.4.22-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/pac-sources", unaffected: make_list("ge 2.4.23-r3"), vulnerable: make_list("lt 2.4.23-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/planet-ccrma-sources", unaffected: make_list("ge 2.4.21-r5"), vulnerable: make_list("lt 2.4.21-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-development-sources", unaffected: make_list("ge 2.6.3_rc1-r1"), vulnerable: make_list("lt 2.6.3_rc1-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources-benh", unaffected: make_list("ge 2.4.22-r5"), vulnerable: make_list("lt 2.4.22-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources-crypto", unaffected: make_list("ge 2.4.20-r3"), vulnerable: make_list("lt 2.4.20-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/ppc-sources-dev", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/selinux-sources", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/sparc-dev-sources", unaffected: make_list("ge 2.6.3_rc1"), vulnerable: make_list("lt 2.6.3_rc1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/sparc-sources", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/usermode-sources", unaffected: make_list("rge 2.4.24-r1", "rge 2.4.26", "ge 2.6.3-r1"), vulnerable: make_list("lt 2.6.3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-prepatch-sources", unaffected: make_list("ge 2.4.25_rc4"), vulnerable: make_list("lt 2.4.25_rc4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.25"), vulnerable: make_list("lt 2.4.25"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/win4lin-sources", unaffected: make_list("eq 2.4.23-r2", "ge 2.6.2-r1"), vulnerable: make_list("lt 2.6.2-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/wolk-sources", unaffected: make_list("eq 4.9-r4", "ge 4.10_pre7-r3"), vulnerable: make_list("lt 4.10_pre7-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/xfs-sources", unaffected: make_list("ge 2.4.24-r2"), vulnerable: make_list("lt 2.4.24-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
