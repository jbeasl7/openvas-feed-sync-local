# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71580");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0217", "CVE-2010-3332", "CVE-2010-3369", "CVE-2010-4159", "CVE-2010-4225", "CVE-2010-4254", "CVE-2011-0989", "CVE-2011-0990", "CVE-2011-0991", "CVE-2011-0992");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:55 -0400 (Fri, 10 Aug 2012)");
  script_name("Gentoo Security Advisory GLSA 201206-13 (mono mono-debugger)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in Mono, the worst of which
allowing for the remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All Mono debugger users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose
'>=dev-util/mono-debugger-2.8.1-r1'


All Mono users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/mono-2.10.2-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=277878");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=342133");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=345561");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=346401");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=351087");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=372983");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201206-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"dev-util/mono-debugger", unaffected: make_list("ge 2.8.1-r1"), vulnerable: make_list("lt 2.8.1-r1"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"dev-lang/mono", unaffected: make_list("ge 2.10.2-r1"), vulnerable: make_list("lt 2.10.2-r1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
