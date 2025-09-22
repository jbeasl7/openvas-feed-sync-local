# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61942");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-03 18:25:22 +0100 (Wed, 03 Dec 2008)");
  script_cve_id("CVE-2008-3651", "CVE-2008-3652");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200812-03 (ipsec-tools)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"IPsec-Tools' racoon is affected by a remote Denial of Service
vulnerability.");
  script_tag(name:"solution", value:"All IPsec-Tools users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-firewall/ipsec-tools-0.7.1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200812-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=232831");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200812-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-firewall/ipsec-tools", unaffected: make_list("ge 0.7.1"), vulnerable: make_list("lt 0.7.1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
