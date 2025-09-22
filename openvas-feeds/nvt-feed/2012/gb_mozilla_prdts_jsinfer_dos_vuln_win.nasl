# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802869");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-1939");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-06-19 15:21:15 +0530 (Tue, 19 Jun 2012)");
  script_name("Mozilla Products 'jsinfer.cpp' Denial of Service Vulnerability - Windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49368");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53797");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49366");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027120");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-34.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service.");
  script_tag(name:"affected", value:"Thunderbird ESR version 10.x before 10.0.5,
  Mozilla Firefox ESR version 10.x before 10.0.5 on Windows");
  script_tag(name:"insight", value:"The 'jsinfer.cpp' function in ESR versions fails to determine data types,
  which allows to cause a denial of service via crafted JavaScript code.");
  script_tag(name:"summary", value:"Mozilla Firefox/Thunderbird is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 10.0.5 or later, upgrade to Mozilla Thunderbird ESR version 10.0.5 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");



  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Firefox/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.4"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"10.0 - 10.0.4");
    security_message(port:0, data:report);
    exit(0);
  }
}

vers = get_kb_item("Thunderbird/Win/Ver");
if(vers)
{
  if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.4"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"10.0 - 10.0.4");
    security_message(port:0, data:report);
    exit(0);
  }
}
