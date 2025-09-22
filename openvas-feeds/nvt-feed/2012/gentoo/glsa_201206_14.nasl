# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71581");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-4370", "CVE-2011-4371", "CVE-2011-4372", "CVE-2011-4373", "CVE-2012-0774", "CVE-2012-0775", "CVE-2012-0776", "CVE-2012-0777");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-03 15:50:00 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:55 -0400 (Fri, 10 Aug 2012)");
  script_name("Gentoo Security Advisory GLSA 201206-14 (acroread)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Adobe Reader might allow remote
attackers to execute arbitrary code or conduct various other attacks.");
  script_tag(name:"solution", value:"All Adobe Reader users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-text/acroread-9.5.1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201206-14");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=405949");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=411499");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201206-14.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"app-text/acroread", unaffected: make_list("ge 9.5.1"), vulnerable: make_list("lt 9.5.1"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
