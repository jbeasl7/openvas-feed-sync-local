# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:schneider_electric:indusoft_web_studio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806642");
  script_version("2024-07-04T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0780");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 16:56:31 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-12-07 13:44:29 +0530 (Mon, 07 Dec 2015)");
  script_name("InduSoft Web Studio 'NTWebServer' Directory Traversal Vulnerability - Windows");

  script_tag(name:"summary", value:"InduSoft Web Studio is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  'NTWebServer' (test web server installed with InduSoft Web Studio).");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to read files outside the web root and possibly perform arbitrary
  code execution.");

  script_tag(name:"affected", value:"InduSoft Web Studio version 7.1
  before SP2 Patch 4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to InduSoft Web Studio version
  7.1 SP2 Patch 4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-14-107-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67056");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_schneider_indusoft_consolidation.nasl");
  script_mandatory_keys("schneider_indusoft/installed");
  script_xref(name:"URL", value:"http://www.indusoft.com/");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!studioVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Version 7.1 SP2 Patch 4 == 7.1.2.4

if (studioVer =~ "^(7.1\.)")
{
  if(version_is_less(version:studioVer, test_version:"7.1.2.4"))
  {
     report = report_fixed_ver(installed_version:studioVer, fixed_version:"7.1.2.4");
     security_message(data:report);
     exit(0);
  }
}
