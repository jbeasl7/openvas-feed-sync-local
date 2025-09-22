# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54863");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-0503");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200502-31 (uim)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Under certain conditions, applications linked against uim suffer from a
privilege escalation vulnerability.");
  script_tag(name:"solution", value:"All uim users should upgrade to the latest available version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-i18n/uim-0.4.5.1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200502-31");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12604");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=82678");
  script_xref(name:"URL", value:"http://lists.freedesktop.org/archives/uim/2005-February/000996.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200502-31.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-i18n/uim", unaffected: make_list("ge 0.4.5.1"), vulnerable: make_list("lt 0.4.5.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
