# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64764");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-1391", "CVE-2009-1884");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200908-07 (Compress-Raw-Zlib Compress-Raw-Bzip2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"An off-by-one error in Compress::Raw::Zlib and Compress::Raw::Bzip2 might
    lead to a Denial of Service.");
  script_tag(name:"solution", value:"All Compress::Raw::Zlib users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =perl-core/Compress-Raw-Zlib-2.020

All Compress::Raw::Bzip2 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =perl-core/Compress-Raw-Bzip2-2.020");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200908-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=273141");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=281955");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200908-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"perl-core/Compress-Raw-Zlib", unaffected: make_list("ge 2.020"), vulnerable: make_list("lt 2.020"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"perl-core/Compress-Raw-Bzip2", unaffected: make_list("ge 2.020"), vulnerable: make_list("lt 2.020"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
