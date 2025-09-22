# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63471");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
  script_cve_id("CVE-2008-2142", "CVE-2008-3949");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200902-06 (emacs edit-utils)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Two vulnerabilities were found in GNU Emacs, possibly leading to
user-assisted execution of arbitrary code. One also affects edit-utils in
XEmacs.");
  script_tag(name:"solution", value:"All GNU Emacs users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-editors/emacs-22.2-r3'

All edit-utils users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-xemacs/edit-utils-2.39'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200902-06");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=221197");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=236498");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200902-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-editors/emacs", unaffected: make_list("ge 22.2-r3", "rge 21.4-r17", "lt 19"), vulnerable: make_list("lt 22.2-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-xemacs/edit-utils", unaffected: make_list("ge 2.39"), vulnerable: make_list("lt 2.39"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
