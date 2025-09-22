# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66148");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3236", "CVE-2009-3237");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Gentoo Security Advisory GLSA 200911-01 (horde horde-webmail horde-groupware)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in the Horde Application Framework can allow for
    arbitrary files to be overwritten and cross-site scripting attacks.");
  script_tag(name:"solution", value:"All Horde users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-3.3.5

All Horde webmail users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-webmail-1.2.4

All Horde groupware users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/horde-groupware-1.2.4");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200911-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=285052");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200911-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/horde", unaffected: make_list("ge 3.3.5"), vulnerable: make_list("lt 3.3.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-webmail", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-apps/horde-groupware", unaffected: make_list("ge 1.2.4"), vulnerable: make_list("lt 1.2.4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
