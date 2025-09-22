# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902445");
  script_version("2025-07-29T05:44:59+0000");
  script_tag(name:"last_modification", value:"2025-07-29 05:44:59 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-06-21 13:52:36 +0200 (Tue, 21 Jun 2011)");
  script_cve_id("CVE-2011-1280");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft XML Editor Information Disclosure Vulnerability (2543893)");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48196");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  # nb: The MSSQL "Consolidation" wasn't added here on purpose and only the SMB Login one was used
  # as the consolidation is not required for the KB check below.
  script_dependencies("smb_reg_service_pack.nasl",
                      "gb_microsoft_sql_server_smb_login_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to gain access to sensitive
  information that may aid in further attacks.");
  script_tag(name:"affected", value:"- Microsoft SQL Server 2005/2008

  - Microsoft Visual Studio 2005/2008/2010

  - Microsoft SQL Server 2005 Management Studio Express");
  script_tag(name:"insight", value:"The flaw is due to an error when resolving XML external entities in
  a Web Service Discovery file ('.disco') and can be exploited to disclose the
  contents of arbitrary files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-049.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-049");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Microsoft SQL Server\";

if(get_kb_item("microsoft/sqlserver/smb-login/detected")) {

  ## Microsoft SQL Server
  if(registry_key_exists(key:key)) {
    foreach item (registry_enum_keys(key:key)) {
      sysPath = registry_get_sz(key:key + item + "\Setup", item:"SQLBinRoot");
      if("Microsoft SQL Server" >< sysPath) {
        sysVer = fetch_file_version(sysPath:sysPath, file_name:"sqlservr.exe");
        if(sysVer) {
          ## SQL Server 2005 Service Pack 3 GDR/QFE, SQL Server 2005 Service Pack 4 GDR/QFE
          ## SQL Server 2008 Service Pack 1 GDR/QFE,  SQL Server 2008 Service Pack 2 GDR/QFE
          ## SQL Server 2008 R2 QFE/GDR
          if(version_in_range(version:sysVer, test_version:"2005.90.4000", test_version2:"2005.90.4059.0")||
             version_in_range(version:sysVer, test_version:"2005.90.4300", test_version2:"2005.90.4339.0")||
             version_in_range(version:sysVer, test_version:"2005.90.5000", test_version2:"2005.90.5056.0")||
             version_in_range(version:sysVer, test_version:"2005.90.5200", test_version2:"2005.90.5291.0")||
             version_in_range(version:sysVer, test_version:"2007.100.2500", test_version2:"2007.100.2572.0")||
             version_in_range(version:sysVer, test_version:"2007.100.2800", test_version2:"2007.100.2840.0")||
             version_in_range(version:sysVer, test_version:"2007.100.4000", test_version2:"2007.100.4063.0")||
             version_in_range(version:sysVer, test_version:"2007.100.4300", test_version2:"2007.100.4310.0")||
             version_in_range(version:sysVer, test_version:"2009.100.1600", test_version2:"2009.100.1616.0")||
             version_in_range(version:sysVer, test_version:"2009.100.1700", test_version2:"2009.100.1789.0")) {
            security_message( port: 0, data: "The target host was found to be vulnerable" );
            exit(0);
          }
        }
      }
    }
  }
}

## SQL Server 2005 Management Studio Express
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    sysPath = registry_get_sz(key:key + item + "\Tools\ShellSEM", item:"InstallDir");
    if("Microsoft SQL Server" >< sysPath)
    {
      sysVer = fetch_file_version(sysPath:sysPath, file_name:"\xml\microsoft.xmleditor.dll");
      if(sysVer)
      {
        if(version_is_less(version:sysVer, test_version:"2.0.50727.5065"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}


## Visual Studio
key = "SOFTWARE\Microsoft\VisualStudio\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    sysPath = registry_get_sz(key:key + item, item:"InstallDir");
    if("Microsoft Visual Studio" >< sysPath)
    {
      sysVer = fetch_file_version(sysPath:sysPath, file_name:"xml\microsoft.xmleditor.dll");
      if(sysVer)
      {
        ## Visual Studio 2010
        ## Visual Studio 2005 SP1
        ## Visual Studio 2008 SP1
        if(version_in_range(version:sysVer, test_version:"2.0", test_version2:"2.0.50727.5064")||
           version_in_range(version:sysVer, test_version:"3.5", test_version2:"3.5.30729.5664")||
           version_in_range(version:sysVer, test_version:"10.0", test_version2:"10.0.30319.461"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}
