# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54605");
  script_cve_id("CVE-2004-0590");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200406-20 (Openswan)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"FreeS/WAN, Openswan, strongSwan and Super-FreeS/WAN contain two bugs when
authenticating PKCS#7 certificates. This could allow an attacker to
authenticate with a fake certificate.");
  script_tag(name:"solution", value:"All FreeS/WAN 1.9x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '=net-misc/freeswan-1.99-r1'
    # emerge '=net-misc/freeswan-1.99-r1'

All FreeS/WAN 2.x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-misc/freeswan-2.04-r1'
    # emerge '>=net-misc/freeswan-2.04-r1'

All Openswan 1.x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '=net-misc/openswan-1.0.6_rc1'
    # emerge '=net-misc/openswan-1.0.6_rc1'

All Openswan 2.x users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-misc/openswan-2.1.4'
    # emerge '>=net-misc/openswan-2.1.4'

All strongSwan users should upgrade to the latest stable version:

    # emerge sync

    # emerge -pv '>=net-misc/strongswan-2.1.3'
    # emerge '>=net-misc/strongswan-2.1.3'

All Super-FreeS/WAN users should migrate to the latest stable version of
Openswan. Note that Portage will force a move for Super-FreeS/WAN users to
Openswan.

    # emerge sync

    # emerge -pv '=net-misc/openswan-1.0.6_rc1'
    # emerge '=net-misc/openswan-1.0.6_rc1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200406-20");
  script_xref(name:"URL", value:"http://lists.openswan.org/pipermail/dev/2004-June/000370.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200406-20.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-misc/freeswan", unaffected: make_list("ge 2.04-r1", "eq 1.99-r1"), vulnerable: make_list("lt 2.04-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/openswan", unaffected: make_list("ge 2.1.4", "eq 1.0.6_rc1"), vulnerable: make_list("lt 2.1.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/strongswan", unaffected: make_list("ge 2.1.3"), vulnerable: make_list("lt 2.1.3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/super-freeswan", unaffected: make_list(), vulnerable: make_list("le 1.99.7.3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
