# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70798");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1168");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:41 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201111-09 (Safe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The Safe module for Perl does not properly restrict code, allowing
    a remote attacker to execute arbitrary Perl code outside of a
restricted
    compartment.");
  script_tag(name:"solution", value:"All users of the standalone Perl Safe module should upgrade to the
      latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=perl-core/Safe-2.27'


All users of the Safe module bundled with Perl should upgrade to the
      latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=virtual/perl-Safe-2.27'


NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since July 18, 2010. It is likely that your system is
already
      no longer affected by this issue.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201111-09");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=325563");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201111-09.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"perl-core/Safe", unaffected: make_list("ge 2.27"), vulnerable: make_list("lt 2.27"))) != NULL ) {
    report += res;
}
if((res = ispkgvuln(pkg:"virtual/perl-Safe", unaffected: make_list("ge 2.27"), vulnerable: make_list("lt 2.27"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
