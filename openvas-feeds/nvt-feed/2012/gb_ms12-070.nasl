# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902689");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-2552");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-10-10 09:46:39 +0530 (Wed, 10 Oct 2012)");
  script_name("Microsoft SQL Server Report Manager Cross Site Scripting Vulnerability (2754849)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2754849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55783");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027623");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/sqlserver/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft SQL Server 2012

  - Microsoft SQL Server 2005 Service Pack 4 and prior

  - Microsoft SQL Server 2008 Service Pack 2 and prior

  - Microsoft SQL Server 2008 Service Pack 3 and prior

  - Microsoft SQL Server 2000 Reporting Services Service Pack 2");

  script_tag(name:"insight", value:"An error exists in the SQL Server Reporting Services (SSRS), which can be
  exploited to insert client-side script code.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host has important security update missing according to
  Microsoft Bulletin MS12-070.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

if(!vers = infos["internal_version"])
  exit(0);

# nb: 2008 (10.x) and earlier should be only affected
if(vers !~ "^([1-9]|10)\.")
  exit(99);

key = "SOFTWARE\Microsoft\Microsoft SQL Server\Reporting Services\Version";
if(registry_key_exists(key:key))
{
  exeVer = registry_get_sz(key:key, item:"Version");

  if(exeVer)
  {
    if(version_is_less(version:exeVer, test_version:"8.0.1077.0"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

key = "SOFTWARE\Microsoft\Microsoft SQL Server\Services\Report Server";
if(!registry_key_exists(key:key)){
   exit(0);
}

key = "SOFTWARE\Microsoft\Microsoft SQL Server\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    sysPath = registry_get_sz(key:key + item + "\Tools\Setup", item:"SQLPath");

    if("Microsoft SQL Server" >< sysPath)
    {
      sysVer = fetch_file_version(sysPath:sysPath, file_name:"Binn\VSShell\Common7\IDE\Microsoft.reportingservices.diagnostics.dll");

      if(sysVer)
      {
        ## SQL Server 2005 Service Pack 4 GDR/QFE,
        ## SQL Server 2008 Service Pack 2 GDR/QFE,  SQL Server 2008 Service Pack 3 GDR/QFE
        ##  SQL Server 2008 R2 SP1 QFE/GDR
        ## SQL Server 2012
        if(version_in_range(version:sysVer, test_version:"9.0.5000", test_version2:"9.0.5068")||
           version_in_range(version:sysVer, test_version:"9.0.5200", test_version2:"9.0.5323"))
## TODO
## Not Tested on SQL 2008 and 2012 ( Due to installer issue)
## MSSQL 2008 R2 (evaluation edition could not apply patch)
## Once fixed uncomment the below code
#           version_in_range(version:sysVer, test_version:"10.00.4000", test_version2:"10.00.4066")||
#           version_in_range(version:sysVer, test_version:"10.00.4260", test_version2:"10.00.4370")||
#           version_in_range(version:sysVer, test_version:"10.00.5500", test_version2:"10.00.5511")||
#           version_in_range(version:sysVer, test_version:"10.00.5750", test_version2:"10.00.5825")||
#           version_in_range(version:sysVer, test_version:"10.50.2500", test_version2:"10.50.2549")||
#           version_in_range(version:sysVer, test_version:"10.50.2750", test_version2:"10.50.2860")||
#           version_in_range(version:sysVer, test_version:"11.0.2100", test_version2:"11.0.2217")||
#           version_in_range(version:sysVer, test_version:"11.0.2300", test_version2:"11.0.2375"))
        {
          security_message(port:port, data:"The target host was found to be vulnerable");
          exit(0);
        }
      }
    }
  }
}
