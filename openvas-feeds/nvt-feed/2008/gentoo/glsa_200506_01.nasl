# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54953");
  script_cve_id("CVE-2005-1704");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200506-01 (binutils)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Various utilities from the GNU Binutils and elfutils packages are
vulnerable to a heap based buffer overflow, potentially resulting in the
execution of arbitrary code.");
  script_tag(name:"solution", value:"All GNU Binutils users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose sys-devel/binutils

All elfutils users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/elfutils-0.108'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200506-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=91398");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=91817");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200506-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-libs/elfutils", unaffected: make_list("ge 0.108"), vulnerable: make_list("lt 0.108"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sys-devel/binutils", unaffected: make_list("rge 2.14.90.0.8-r3", "rge 2.15.90.0.1.1-r5", "rge 2.15.90.0.3-r5", "rge 2.15.91.0.2-r2", "rge 2.15.92.0.2-r10", "ge 2.16-r1"), vulnerable: make_list("lt 2.16-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
