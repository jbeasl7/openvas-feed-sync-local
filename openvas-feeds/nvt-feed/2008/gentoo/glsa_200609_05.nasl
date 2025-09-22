# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57883");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2006-4339");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Gentoo Security Advisory GLSA 200609-05 (openssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"OpenSSL fails to properly validate PKCS #1 v1.5 signatures.");
  script_tag(name:"solution", value:"All OpenSSL users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/openssl-0.9.7k'

All AMD64 x86 emulation base libraries users should upgrade to the latest
version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-emulation/emul-linux-x86-baselibs-2.5.2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200609-05");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=146375");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=146438");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200609-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-libs/openssl", unaffected: make_list("ge 0.9.7k"), vulnerable: make_list("lt 0.9.7k"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-emulation/emul-linux-x86-baselibs", unaffected: make_list("ge 2.5.2"), vulnerable: make_list("lt 2.5.2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
