# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54737");
  script_cve_id("CVE-2004-1010");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200411-16 (zip)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"zip contains a buffer overflow when creating a ZIP archive of files with
very long path names. This could lead to the execution of arbitrary code.");
  script_tag(name:"solution", value:"All zip users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-arch/zip-2.3-r4'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-16");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=70227");
  script_xref(name:"URL", value:"http://www.hexview.com/docs/20041103-1.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200411-16.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-arch/zip", unaffected: make_list("ge 2.3-r4"), vulnerable: make_list("le 2.3-r3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
