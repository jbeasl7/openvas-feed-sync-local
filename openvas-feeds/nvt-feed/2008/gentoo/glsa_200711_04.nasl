# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58743");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-3257");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200711-04 (evolution-data-server)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The IMAP client of Evolution contains a vulnerability potentially leading
to the execution of arbitrary code.");
  script_tag(name:"solution", value:"Note that this GLSA addresses the same issue as GLSA 200707-03, but for the
1.10 branch of Evolution Data Server.

All Evolution users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=gnome-extra/evolution-data-server-1.10.3.1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200711-04");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=190861");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200707-03.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200711-04.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"gnome-extra/evolution-data-server", unaffected: make_list("ge 1.10.3.1"), vulnerable: make_list("lt 1.10.3.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
