# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802152");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2990", "CVE-2011-2993");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Information Disclosure and Security Bypass Vulnerabilities - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49246");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49248");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-29.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl",
                      "gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  and bypass the application's security mechanism.");
  script_tag(name:"affected", value:"SeaMonkey version 2.0 through 2.2
  Mozilla Firefox version 4.x through 5");
  script_tag(name:"insight", value:"The flaws are due to implementation errors,

  - In Content Security Policy (CSP) violation reports, which fails to remove
    proxy-authorization credentials from the listed request headers.

  - In digital signatures for JAR files, which fails to prevent calls from
    unsigned JavaScript code to signed code.");
  script_tag(name:"summary", value:"Mozilla Firefox/Seamonkey is prone to information disclosure and security bypass vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 6.0 or later, Upgrade to SeaMonkey version to 2.3 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"4.0", test_version2:"5.0.1"))
  {
     report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.0 - 5.0.1");
     security_message(port: 0, data: report);
     exit(0);
  }
}

vers = get_kb_item("Seamonkey/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"2.0", test_version2:"2.2")){
     report = report_fixed_ver(installed_version:vers, vulnerable_range:"2.0 - 2.2");
     security_message(port: 0, data: report);
  }
}
