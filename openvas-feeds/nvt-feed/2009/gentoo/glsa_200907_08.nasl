# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64430");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-0282");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200907-08 (rt2400 rt2500 rt2570 rt61 ralink-rt61)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"An integer overflow in multiple Ralink wireless drivers might lead to the
execution of arbitrary code with elevated privileges.");
  script_tag(name:"solution", value:"All external kernel modules have been masked and we recommend that
users unmerge those drivers. The Linux mainline kernel has equivalent
support for these devices and the vulnerability has been resolved in
stable versions of sys-kernel/gentoo-sources.

    # emerge --unmerge 'net-wireless/rt2400'
    # emerge --unmerge 'net-wireless/rt2500'
    # emerge --unmerge 'net-wireless/rt2570'
    # emerge --unmerge 'net-wireless/rt61'
    # emerge --unmerge 'net-wireless/ralink-rt61'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200907-08");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=257023");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200907-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-wireless/rt2400", unaffected: make_list(), vulnerable: make_list("le 1.2.2_beta3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/rt2500", unaffected: make_list(), vulnerable: make_list("le 1.1.0_pre2007071515"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/rt2570", unaffected: make_list(), vulnerable: make_list("le 20070209"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/rt61", unaffected: make_list(), vulnerable: make_list("le 1.1.0_beta2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-wireless/ralink-rt61", unaffected: make_list(), vulnerable: make_list("le 1.1.1.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
