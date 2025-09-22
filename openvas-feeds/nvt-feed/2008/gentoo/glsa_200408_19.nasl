# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54649");
  script_cve_id("CVE-2004-0777");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200408-19 (courier-imap)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"There is a format string vulnerability in non-standard configurations of
courier-imapd which may be exploited remotely. An attacker may be able to
execute arbitrary code as the user running courier-imapd (oftentimes
root).");
  script_tag(name:"solution", value:"All courier-imap users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=net-mail/courier-imap-3.0.5'
    # emerge '>=net-mail/courier-imap-3.0.5'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200408-19");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=60865");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=131&type=vulnerabilities&flashstatus=true");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200408-19.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-mail/courier-imap", unaffected: make_list("ge 3.0.5"), vulnerable: make_list("le 3.0.2-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
