# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58698");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-1536", "CVE-2007-2799");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200710-19 (sleuthkit)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"An integer underflow vulnerability has been reported in The Sleuth Kit
allowing for the user-assisted execution of arbitrary code.");
  script_tag(name:"solution", value:"All The Sleuth Kit users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-forensics/sleuthkit-2.0.9'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200710-19");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=181977");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200703-26.xml");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200705-25.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200710-19.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-forensics/sleuthkit", unaffected: make_list("ge 2.0.9"), vulnerable: make_list("lt 2.0.9"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
