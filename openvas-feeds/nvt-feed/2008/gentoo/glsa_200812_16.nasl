# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62965");
  script_version("2024-01-23T05:05:19+0000");
  script_tag(name:"last_modification", value:"2024-01-23 05:05:19 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"creation_date", value:"2008-12-23 18:28:16 +0100 (Tue, 23 Dec 2008)");
  script_cve_id("CVE-2008-4577", "CVE-2008-4578", "CVE-2008-4870", "CVE-2008-4907");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 02:46:00 +0000 (Sun, 21 Jan 2024)");
  script_name("Gentoo Security Advisory GLSA 200812-16 (dovecot)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in the Dovecot mailserver.");
  script_tag(name:"solution", value:"All Dovecot users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/dovecot-1.1.7-r1'

Users should be aware that dovecot.conf will still be world-readable after
the update. If employing ssl_key_password, it should not be used in
dovecot.conf but in a separate file which should be included with
'include_try'.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200812-16");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=240409");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=244962");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=245316");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200812-16.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-mail/dovecot", unaffected: make_list("ge 1.1.7-r1"), vulnerable: make_list("lt 1.1.7-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
