# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54936");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-1431");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200505-04 (GnuTLS)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The GnuTLS library is vulnerable to Denial of Service attacks.");
  script_tag(name:"solution", value:"All GnuTLS users should remove the existing installation and upgrade to the
latest version:

    # emerge --sync
    # emerge --unmerge gnutls
    # emerge --ask --oneshot --verbose net-libs/gnutls

Due to small API changes with the previous version, please do the
following to ensure your applications are using the latest GnuTLS that you
just emerged.

    # revdep-rebuild --soname-regexp libgnutls.so.1[01]

Previously exported RSA keys can be fixed by executing the following
command on the key files:

    # certtool -k infile outfile");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200505-04");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=90726");
  script_xref(name:"URL", value:"http://lists.gnupg.org/pipermail/gnutls-dev/2005-April/000858.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200505-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-libs/gnutls", unaffected: make_list("ge 1.2.3", "rge 1.0.25"), vulnerable: make_list("lt 1.2.3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
