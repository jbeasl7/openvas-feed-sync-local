# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71165");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-0751", "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754", "CVE-2012-0755", "CVE-2012-0756", "CVE-2012-0767");
  script_version("2025-02-17T05:38:47+0000");
  script_tag(name:"last_modification", value:"2025-02-17 05:38:47 +0000 (Mon, 17 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 16:05:58 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
  script_name("FreeBSD Ports: linux-f10-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: linux-f10-flashplugin

CVE-2012-0751
The ActiveX control in Adobe Flash Player before 10.3.183.15 and 11.x
before 11.1.102.62 on Windows allows attackers to execute arbitrary
code or cause a denial of service (memory corruption) via unspecified
vectors.

CVE-2012-0752
Adobe Flash Player before 10.3.183.15 and 11.x before 11.1.102.62 on
Windows, Mac OS X, Linux, and Solaris, before 11.1.111.6 on Android
2.x and 3.x, and before 11.1.115.6 on Android 4.x allows attackers to
execute arbitrary code or cause a denial of service (memory
corruption) via leveraging an unspecified 'type confusion.'

CVE-2012-0753
Adobe Flash Player before 10.3.183.15 and 11.x before 11.1.102.62 on
Windows, Mac OS X, Linux, and Solaris, before 11.1.111.6 on Android
2.x and 3.x, and before 11.1.115.6 on Android 4.x allows attackers to
execute arbitrary code or cause a denial of service (memory
corruption) via crafted MP4 data.

CVE-2012-0754
Adobe Flash Player before 10.3.183.15 and 11.x before 11.1.102.62 on
Windows, Mac OS X, Linux, and Solaris, before 11.1.111.6 on Android
2.x and 3.x, and before 11.1.115.6 on Android 4.x allows attackers to
execute arbitrary code or cause a denial of service (memory
corruption) via unspecified vectors.

CVE-2012-0755
Adobe Flash Player before 10.3.183.15 and 11.x before 11.1.102.62 on
Windows, Mac OS X, Linux, and Solaris, before 11.1.111.6 on Android
2.x and 3.x, and before 11.1.115.6 on Android 4.x allows attackers to
bypass intended access restrictions via unspecified vectors, a
different vulnerability than CVE-2012-0756.

CVE-2012-0756
Adobe Flash Player before 10.3.183.15 and 11.x before 11.1.102.62 on
Windows, Mac OS X, Linux, and Solaris, before 11.1.111.6 on Android
2.x and 3.x, and before 11.1.115.6 on Android 4.x allows attackers to
bypass intended access restrictions via unspecified vectors, a
different vulnerability than CVE-2012-0755.

CVE-2012-0767
Cross-site scripting (XSS) vulnerability in Adobe Flash Player before
10.3.183.15 and 11.x before 11.1.102.62 on Windows, Mac OS X, Linux,
and Solaris, before 11.1.111.6 on Android 2.x and 3.x, and before
11.1.115.6 on Android 4.x allows remote attackers to inject arbitrary
web script or HTML via unspecified vectors, aka 'Universal XSS
(UXSS), ' as exploited in the wild in February 2012.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb12-03.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f63bf080-619d-11e1-91af-003067b2972c.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"11.1r102.62")<0) {
  txt += "Package linux-f10-flashplugin version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}