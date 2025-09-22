# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900832");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2935", "CVE-2009-2973");
  script_name("Google Chrome 'JavaScript' And 'HTTPS' Multiple Vulnerabilities (Aug 2009)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36417");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36149");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2420");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2009/08/stable-update-security-fixes.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to spoof the X.509 certificate.");
  script_tag(name:"affected", value:"Google Chrome version prior to 2.0.172.43 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - When 'Google V8' is used in the application, it allows to bypass intended
    restrictions on reading memory, and possibly obtain sensitive information
    in the Chrome sandbox, via crafted JavaScript.

  - Application fails to prevent SSL connections to a site with an X.509
    certificate signed with the MD2 or MD4 algorithm, which makes it easier for
    man-in-the-middle attackers to spoof arbitrary HTTPS servers via a crafted
    certificate.");
  script_tag(name:"solution", value:"Upgrade to version 2.0.172.43 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer)
  exit(0);

if(version_is_less(version:chromeVer, test_version:"2.0.172.43")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"2.0.172.43");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
