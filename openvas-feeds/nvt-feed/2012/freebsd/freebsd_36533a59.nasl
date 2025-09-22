# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72611");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-5248", "CVE-2012-5249", "CVE-2012-5250", "CVE-2012-5251", "CVE-2012-5252", "CVE-2012-5253", "CVE-2012-5254", "CVE-2012-5255", "CVE-2012-5256", "CVE-2012-5257", "CVE-2012-5258", "CVE-2012-5259", "CVE-2012-5260", "CVE-2012-5261", "CVE-2012-5262", "CVE-2012-5263", "CVE-2012-5264", "CVE-2012-5265", "CVE-2012-5266", "CVE-2012-5267", "CVE-2012-5269", "CVE-2012-5270", "CVE-2012-5271", "CVE-2012-5272", "CVE-2012-5285", "CVE-2012-5286", "CVE-2012-5287", "CVE-2012-5673", "CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037", "CVE-2012-2038", "CVE-2012-2039", "CVE-2012-2040");
  script_version("2025-02-17T05:38:47+0000");
  script_tag(name:"last_modification", value:"2025-02-17 05:38:47 +0000 (Mon, 17 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 16:05:35 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
  script_name("FreeBSD Ports: linux-f10-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: linux-f10-flashplugin

CVE-2012-5248
Buffer overflow in Adobe Flash Player before 10.3.183.29 and 11.x
before 11.4.402.287 on Windows and Mac OS X, before 10.3.183.29 and
11.x before 11.2.202.243 on Linux, before 11.1.111.19 on Android 2.x
and 3.x, and before 11.1.115.20 on Android 4.x, Adobe AIR before
3.4.0.2710, and Adobe AIR SDK before 3.4.0.2710 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than other Flash Player buffer overflow CVEs listed in
APSB12-22.

CVE-2012-5249
Buffer overflow in Adobe Flash Player before 10.3.183.29 and 11.x
before 11.4.402.287 on Windows and Mac OS X, before 10.3.183.29 and
11.x before 11.2.202.243 on Linux, before 11.1.111.19 on Android 2.x
and 3.x, and before 11.1.115.20 on Android 4.x, Adobe AIR before
3.4.0.2710, and Adobe AIR SDK before 3.4.0.2710 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than other Flash Player buffer overflow CVEs listed in
APSB12-22.

CVE-2012-5250
Buffer overflow in Adobe Flash Player before 10.3.183.29 and 11.x
before 11.4.402.287 on Windows and Mac OS X, before 10.3.183.29 and
11.x before 11.2.202.243 on Linux, before 11.1.111.19 on Android 2.x
and 3.x, and before 11.1.115.20 on Android 4.x, Adobe AIR before
3.4.0.2710, and Adobe AIR SDK before 3.4.0.2710 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than other Flash Player buffer overflow CVEs listed in
APSB12-22.

Text truncated. Please see the references for more information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb12-22.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/36533a59-2770-11e2-bb44-003067b2972c.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"11.2r202.238")<=0) {
  txt += "Package linux-f10-flashplugin version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}