# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812594");
  script_version("2025-08-01T15:45:48+0000");
  script_cve_id("CVE-2018-1028");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-21 17:56:00 +0000 (Mon, 21 May 2018)");
  script_tag(name:"creation_date", value:"2018-04-11 10:43:18 +0530 (Wed, 11 Apr 2018)");
  script_name("Microsoft Office Web Apps 2010 Service Pack 2 RCE Vulnerability (KB4018360)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4018360");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Office graphics component
  improperly handles specially crafted embedded fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take control of the affected system and execute the arabitarty code.");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4018360");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Web/Apps/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

webappVer = infos["version"];
path = infos["location"];
if(!path || "Could not find the install location" >< path)
  exit(0);

if(webappVer =~ "^14\.")
{
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7197.4999"))
    {
      report = report_fixed_ver(file_checked: path + "\14.0\WebServices\ConversionService\Bin\Converter\sword.dll",
                            file_version:dllVer, vulnerable_range:"14.0 - 14.0.7197.4999");
      security_message(data:report);
      exit(0);
    }
  }
}
exit(0);
