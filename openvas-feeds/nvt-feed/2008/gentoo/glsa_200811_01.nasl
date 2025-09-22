# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61856");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-11-19 16:52:57 +0100 (Wed, 19 Nov 2008)");
  script_cve_id("CVE-2008-4195", "CVE-2008-4196", "CVE-2008-4197", "CVE-2008-4198", "CVE-2008-4199", "CVE-2008-4200", "CVE-2008-4292", "CVE-2008-4694", "CVE-2008-4695", "CVE-2008-4696", "CVE-2008-4697", "CVE-2008-4698", "CVE-2008-4794", "CVE-2008-4795");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 20:37:25 +0000 (Thu, 15 Feb 2024)");
  script_name("Gentoo Security Advisory GLSA 200811-01 (opera)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Opera, allowing for the
execution of arbitrary code.");
  script_tag(name:"solution", value:"All Opera users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/opera-9.62'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200811-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=235298");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=240500");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=243060");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=244980");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200811-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-client/opera", unaffected: make_list("ge 9.62"), vulnerable: make_list("lt 9.62"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
