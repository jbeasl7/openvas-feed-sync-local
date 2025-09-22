# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-4010", "CVE-2012-4142", "CVE-2012-4143", "CVE-2012-4144", "CVE-2012-4145", "CVE-2012-4146");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-26 11:20:50 -0400 (Wed, 26 Sep 2012)");
  script_name("Gentoo Security Advisory GLSA 201209-11 (opera)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in Opera, the worst of
which may allow remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All Opera users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/opera-12.01.1532'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=429478");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=434584");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1201/");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201209-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-client/opera", unaffected: make_list("ge 12.01.1532"), vulnerable: make_list("lt 12.01.1532"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
