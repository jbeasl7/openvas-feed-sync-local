# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800082");
  script_version("2024-07-11T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-07-11 05:05:33 +0000 (Thu, 11 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5416");
  script_name("Microsoft SQL Server sp_replwritetovarbin() BOF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/sqlserver/smb-login/detected");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Dec/1021363.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32710");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/961040.mspx");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/499042/100/0/threaded");
  script_xref(name:"URL", value:"http://www.sec-consult.com/files/20081209_mssql-2000-sp_replwritetovarbin_memwrite.txt");

  script_tag(name:"impact", value:"Successful exploitation could result in heap based buffer overflow via
  specially crafted arguments passed to the affected application.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2000 and 2005.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in the implementation of the
  function sp_replwritetovarbin() SQL procedure.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-004.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

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

# nb: 2005 (9.x) and earlier should be only affected
if(vers !~ "^[1-9]\.")
  exit(99);

function Get_FileVersion(ver, path)
{
  if(ver == "MS SQL Server 2005")
  {
    item = "SQLBinRoot";
    file = "\sqlservr.exe";
  }

  if(ver == "MS SQL Server 2000")
  {
    item = "InstallLocation";
    file = "\Binn\sqlservr.exe";
  }

  sqlFile = registry_get_sz(key:path, item:item);
  if(!sqlFile){
    exit(0);
  }

  sqlFile += file;
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:sqlFile);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:sqlFile);

  fileVer = GetVer(file:file, share:share);
  if(!fileVer){
    return 0;
  }
  else return fileVer;
}

# Retrieving Microsoft SQL Server 2005 Registry entry
if(registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2005")){
  msSqlSer = "MS SQL Server 2005";
}
# Retrieving Microsoft SQL Server 2000 Registry entry
else if (registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2000")){
  msSqlSer = "MS SQL Server 2000";
}

if(!msSqlSer){
  exit(0);
}

if(msSqlSer == "MS SQL Server 2005")
{
  reqSqlVer = "2005.90.3077.0";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.1\Setup");
}
else if(msSqlSer == "MS SQL Server 2000")
{
  reqSqlVer = "2000.80.2055.0";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2000");
}

if(!insSqlVer){
  exit(0);
}

if(version_is_less(version:insSqlVer, test_version:reqSqlVer)){
  report = report_fixed_ver(installed_version:insSqlVer, fixed_version:reqSqlVer);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
