# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54524");
  script_cve_id("CVE-2004-0001");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200402-06 (Kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A vulnerability has been discovered by in the ptrace emulation code for
AMD64 platforms when eflags are processed, allowing a local user to obtain
elevated privileges.");
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

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200402-06");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200402-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-kernel/ck-sources", unaffected: make_list("ge 2.6.2"), vulnerable: make_list("lt 2.6.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/development-sources", unaffected: make_list("ge 2.6.2"), vulnerable: make_list("lt 2.6.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-dev-sources", unaffected: make_list("ge 2.6.2"), vulnerable: make_list("lt 2.6.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-sources", unaffected: make_list("ge 2.4.22-r6"), vulnerable: make_list("lt 2.4.22-r6"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gentoo-test-sources", unaffected: make_list("ge 2.6.2-r1"), vulnerable: make_list("lt 2.6.2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/gs-sources", unaffected: make_list("ge 2.4.25_pre7-r1"), vulnerable: make_list("lt 2.4.25_pre7-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-prepatch-sources", unaffected: make_list("ge 2.4.25_rc3"), vulnerable: make_list("lt 2.4.25_rc3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-kernel/vanilla-sources", unaffected: make_list("ge 2.4.24-r1"), vulnerable: make_list("lt 2.4.24-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
