# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72457");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1570", "CVE-2009-3909", "CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543", "CVE-2011-1178", "CVE-2011-2896", "CVE-2012-2763", "CVE-2012-3402");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-03 11:11:28 -0400 (Wed, 03 Oct 2012)");
  script_name("Gentoo Security Advisory GLSA 201209-23 (gimp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in GIMP, the worst of
    which allow execution of arbitrary code or Denial of Service.");
  script_tag(name:"solution", value:"All GIMP users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-gfx/gimp-2.6.12-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201209-23");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=293127");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=350915");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=372975");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=379289");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=418425");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=432582");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201209-23.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"media-gfx/gimp", unaffected: make_list("ge 2.6.12-r2"), vulnerable: make_list("lt 2.6.12-r2"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
