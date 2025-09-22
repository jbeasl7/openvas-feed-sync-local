# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70820");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-4091", "CVE-2011-0562", "CVE-2011-0563", "CVE-2011-0565", "CVE-2011-0566", "CVE-2011-0567", "CVE-2011-0570", "CVE-2011-0585", "CVE-2011-0586", "CVE-2011-0587", "CVE-2011-0588", "CVE-2011-0589", "CVE-2011-0590", "CVE-2011-0591", "CVE-2011-0592", "CVE-2011-0593", "CVE-2011-0594", "CVE-2011-0595", "CVE-2011-0596", "CVE-2011-0598", "CVE-2011-0599", "CVE-2011-0600", "CVE-2011-0602", "CVE-2011-0603", "CVE-2011-0604", "CVE-2011-0605", "CVE-2011-0606", "CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2137", "CVE-2011-2138", "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414", "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417", "CVE-2011-2424", "CVE-2011-2425", "CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434", "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438", "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442", "CVE-2011-2462", "CVE-2011-4369");
  script_version("2024-07-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:39 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:21:09 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:42 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201201-19 (acroread)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Adobe Reader might allow remote
    attackers to execute arbitrary code or conduct various other attacks.");
  script_tag(name:"solution", value:"All Adobe Reader users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-text/acroread-9.4.7'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201201-19");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=354211");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=382969");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=393481");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201201-19.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"app-text/acroread", unaffected: make_list("ge 9.4.7"), vulnerable: make_list("lt 9.4.7"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
