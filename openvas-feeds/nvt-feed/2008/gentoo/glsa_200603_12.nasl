# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56420");
  script_cve_id("CVE-2006-1269");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200603-12 (zoo)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A buffer overflow in zoo may be exploited to execute arbitrary when
creating archives of specially crafted directories and files.");
  script_tag(name:"solution", value:"All zoo users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-arch/zoo-2.10-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200603-12");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=125622");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=183426");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200603-12.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-arch/zoo", unaffected: make_list("ge 2.10-r2"), vulnerable: make_list("lt 2.10-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
