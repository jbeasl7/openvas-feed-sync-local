# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61785");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
  script_cve_id("CVE-2008-4394");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200810-02 (portage)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A search path vulnerability in Portage allows local attackers to execute
commands with root privileges if emerge is called from untrusted
directories.");
  script_tag(name:"solution", value:"All Portage users should upgrade to the latest version:

    # cd /root
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-apps/portage-2.1.4.5'

NOTE: To upgrade to Portage 2.1.4.5 using 2.1.4.4 or prior, you must run
emerge from a trusted working directory, such as '/root'.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200810-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=239560");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200810-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-apps/portage", unaffected: make_list("ge 2.1.4.5"), vulnerable: make_list("lt 2.1.4.5"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
