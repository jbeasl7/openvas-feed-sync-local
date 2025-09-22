# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804012");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1726",
                "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736",
                "CVE-2013-1737");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-09-24 15:40:41 +0530 (Tue, 24 Sep 2013)");
  script_name("Mozilla Thunderbird ESR Multiple Vulnerabilities-01 (Sep 2013) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird ESR is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird ESR version 17.0.9 or later.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"affected", value:"Mozilla Thunderbird ESR version 17.x before 17.0.9 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain escalated privileges,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54896");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62460");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62463");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62475");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62479");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62482");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-88.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^17\." && version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.8"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
