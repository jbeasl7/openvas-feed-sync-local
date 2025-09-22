# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800105");
  script_version("2024-07-11T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-07-11 05:05:33 +0000 (Thu, 11 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-10-14 16:26:50 +0200 (Tue, 14 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0085", "CVE-2008-0086", "CVE-2008-0106", "CVE-2008-0107");
  script_xref(name:"CB-A", value:"08-0110");
  script_name("Microsoft SQL Server Elevation of Privilege Vulnerabilities (941203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/sqlserver/smb-login/detected");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30119");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-040");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code,
  with a crafted SQL expression or Exposure of sensitive information or
  Privilege escalation.");

  script_tag(name:"affected", value:"- Microsoft SQL Server 2000 Service Pack 4

  - Microsoft SQL Server 2005 Service Pack 2

  - Microsoft SQL Server 2005 Edition Service Pack 2

  - Microsoft SQL Server 2005 Express Edition Service Pack 2

  - Microsoft SQL Server 2005 Express Edition with Advanced Services Service Pack 2");

  script_tag(name:"insight", value:"The flaws are due to

  - error when initializing memory pages, while reallocating memory.

  - buffer overflow error in the convert function, while handling malformed
    input strings.

  - memory corruption error, while handling malformed data structures in
    on-disk files.

  - buffer overflow error, while processing malformed insert statements.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host has Microsoft SQL Server, which is prone to Privilege
  Escalation Vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
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
    offset = 28000000;
  }

  if(ver == "MS SQL Server 2000")
  {
    item = "InstallLocation";
    file = "\Binn\sqlservr.exe";
    offset = 7800000;
  }

  sqlFile = registry_get_sz(key:path ,item:item);
  if(!sqlFile){
    exit(0);
  }

  sqlFile += file;
  v = get_version(dllPath:sqlFile, string:"prod", offs:offset);

  return v;
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

if(msSqlSer == "MS SQL Server 2005"){
  reqSqlVer = "9.00.3068.00";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.1\Setup");
}
else if(msSqlSer == "MS SQL Server 2000"){
  reqSqlVer = "8.00.2050";
  insSqlVer = Get_FileVersion(ver:msSqlSer, path:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2000");
}

if(!insSqlVer){
  exit(0);
}

if(version_is_greater(version:reqSqlVer, test_version:insSqlVer)){
  report = report_fixed_ver(installed_version:insSqlVer, fixed_version:reqSqlVer);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
