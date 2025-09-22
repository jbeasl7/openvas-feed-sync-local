# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811206");
  script_version("2024-07-26T05:05:35+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-7269");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 14:01:24 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-06-16 12:56:08 +0530 (Fri, 16 Jun 2017)");
  script_name("Microsoft Windows 'WebDAV' Remote Code Execution Vulnerability (KB3197835)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3197835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97127");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB3197835.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in IIS when
  WebDAV improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of current user.");

  script_tag(name:"affected", value:"- Microsoft Windows XP SP2 x64

  - Microsoft Windows XP SP3 x86

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("misc_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");

if( hotfix_check_sp( xp:4, xpx64:3, win2003:3, win2003x64:3 ) <= 0 )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

# TODO: Limit to a possible known common path
fileList = wmi_file_fileversion( handle:handle, fileName:"httpext", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

maxVer = ""; # nb: To make openvas-nasl-lint happy...
foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( maxVer && version_is_less( version:version[1], test_version:maxVer ) ) {
      continue;
    } else {
      foundMax = TRUE;
      maxVer = version[1];
      maxPath = filePath;
    }
  }
}

if( foundMax ) {
  if( hotfix_check_sp( xp:4 ) > 0 ) {
    if( version_is_less( version:maxVer, test_version:"6.0.2600.7150" ) ) {
      Vulnerable_range = "Less than 6.0.2600.7150";
      VULN = TRUE;
    }
  }

  else if( hotfix_check_sp( win2003:3, win2003x64:3, xpx64:3 ) > 0 ) {
    if( version_is_less( version:maxVer, test_version:"6.0.3790.5955" ) ) {
      Vulnerable_range = "Less than 6.0.3790.5955";
      VULN = TRUE;
    }
  }
}

if( VULN ) {
  report = report_fixed_ver( file_version:maxVer, file_checked:maxPath, vulnerable_range:Vulnerable_range );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
