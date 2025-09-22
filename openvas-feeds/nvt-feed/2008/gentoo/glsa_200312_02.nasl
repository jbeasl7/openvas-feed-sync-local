# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54508");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2003-0961");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200312-02 (Kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A flaw in the do_brk() function of the Linux kernel 2.4.22 and earlier can
be exploited by local users or malicious services to gain root privileges.");
  script_tag(name:"solution", value:"It is recommended that all Gentoo Linux users upgrade their machines to use
the latest stable version of their preferred kernel sources.

    # emerge sync
    # emerge -pv [your preferred kernel sources]
    # emerge [your preferred kernel sources]
    # [update the /usr/src/linux symlink]
    # [compile and install your new kernel]
    # [emerge any necessary kernel module ebuilds]
    # [reboot]");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200312-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9138");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=34844");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200312-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"aa-sources", unaffected: make_list("ge 2.4.23_pre6-r3"), vulnerable: make_list("lt 2.4.23_pre6-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ck-sources", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"gentoo-sources", unaffected: make_list("ge 2.4.20-r9"), vulnerable: make_list("lt 2.4.20-r9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"gentoo-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"grsec-sources", unaffected: make_list("ge 2.4.22.1.9.12-r1"), vulnerable: make_list("lt 2.4.22.1.9.12-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"grsec-sources", unaffected: make_list("ge 2.4.22.2.0_rc3-r1"), vulnerable: make_list("lt 2.4.22.2.0_rc3-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"gs-sources", unaffected: make_list("ge 2.4.23_pre8-r1"), vulnerable: make_list("lt 2.4.23_pre8-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"hardened-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"hardened-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ia64-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mips-sources", unaffected: make_list("ge 2.4.22-r4"), vulnerable: make_list("lt 2.4.22-r4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mips-sources", unaffected: make_list("ge 2.4.22-r5"), vulnerable: make_list("lt 2.4.22-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"openmosix-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-benh", unaffected: make_list("ge 2.4.20-r9"), vulnerable: make_list("lt 2.4.20-r9"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-benh", unaffected: make_list("ge 2.4.21-r2"), vulnerable: make_list("lt 2.4.21-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-benh", unaffected: make_list("ge 2.4.22-r3"), vulnerable: make_list("lt 2.4.22-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"ppc-sources-crypto", unaffected: make_list("ge 2.4.20-r1"), vulnerable: make_list("lt 2.4.20-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"selinux-sources", unaffected: make_list("ge 2.4.21-r5"), vulnerable: make_list("lt 2.4.21-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sparc-sources", unaffected: make_list("ge 2.4.23"), vulnerable: make_list("lt 2.4.23"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"usermode-sources", unaffected: make_list("ge 2.4.22-r1"), vulnerable: make_list("lt 2.4.22-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"wolk-sources", unaffected: make_list("ge 4.10_pre7-r1"), vulnerable: make_list("lt 4.10_pre7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"wolk-sources", unaffected: make_list("ge 4.9-r2"), vulnerable: make_list("lt 4.9-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"xfs-sources", unaffected: make_list("ge 2.4.20-r4"), vulnerable: make_list("lt 2.4.20-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
