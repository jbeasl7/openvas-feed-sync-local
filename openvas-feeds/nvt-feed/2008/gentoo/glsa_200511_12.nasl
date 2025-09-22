# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55878");
  script_cve_id("CVE-2005-3486", "CVE-2005-3487", "CVE-2005-3488");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200511-12 (scorched3d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Scorched 3D allow a remote attacker to deny
service or execute arbitrary code on game servers.");
  script_tag(name:"solution", value:"The Scorched 3D package has been hard-masked until a new version correcting
these flaws is released. In the meantime, current users are advised to
unmerge the package:

    # emerge --unmerge games-strategy/scorched3d");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200511-12");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=111421");
  script_xref(name:"URL", value:"http://seclists.org/lists/fulldisclosure/2005/Nov/0079.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200511-12.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"games-strategy/scorched3d", unaffected: make_list(), vulnerable: make_list("le 39.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
