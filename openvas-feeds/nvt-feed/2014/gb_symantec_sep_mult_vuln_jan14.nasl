# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804199");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-5009", "CVE-2013-5010", "CVE-2013-5011");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-01-27 16:29:04 +0530 (Mon, 27 Jan 2014)");
  script_name("Symantec Endpoint Protection Multiple Vulnerabilities (Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");

  script_xref(name:"URL", value:"http://www.symantec.com/connect/articles/what-are-symantec-endpoint-protection-sep-versions-released-officialy");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64128");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64129");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64130");

  script_tag(name:"summary", value:"Symantec Endpoint Protection is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to:

  - application not properly verifying the authentication of authorised users.

  - an unspecified error in Application/Device Control (ADC) component.

  - an unquoted search path.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to gain escalated privileges
  and access sensitive files or directories.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection (SEP) 11.x before version 11.0.7.4 and 12.x
  before 12.1.2 RU2 and Endpoint Protection Small Business Edition 12.x before 12.1.2 RU2");

  script_tag(name:"solution", value:"Upgrade to Symantec Endpoint Protection (SEP) version 11.0.7.4 or 12.1.2 RU2
  or Endpoint Protection Small Business Edition 12.x before version 12.1.2RU2.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE))
  exit(0);

sepType = get_kb_item("Symantec/SEP/SmallBusiness");

##  Check for vulnerable version 11.0.7.4 = 11.0.7400.1398
if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"11.0", test_version2:"11.0.7400.1397")||
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.2015.2014"))
{
   security_message( port: 0, data: "The target host was found to be vulnerable" );
   exit(0);
}

if("sepsb" >< sepType && sepVer =~ "^12\." &&
   version_is_less(version:sepVer, test_version:"12.1.2015.2015"))
{
   security_message( port: 0, data: "The target host was found to be vulnerable" );
   exit(0);
}
