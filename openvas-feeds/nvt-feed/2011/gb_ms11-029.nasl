# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902365");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0041");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft GDI+ Remote Code Execution Vulnerability (2489979)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0946");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47250");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-029");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary code
  via a specially crafted web page.");

  script_tag(name:"affected", value:"- Microsoft Windows XP x32 Edition Service Pack 3 and prior

  - Microsoft Windows XP x64 Edition Service Pack 2 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is caused by an integer overflow error in the GDI+ library when
  processing malformed data.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-029.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("misc_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");

if( hotfix_check_sp( xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win2008:3 ) <= 0 )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

# TODO: Limit to a possible known common path
fileList = wmi_file_fileversion( handle:handle, fileName:"gdiplus", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

maxVer = ""; # nb: To make openvas-nasl-lint happy...
fix = "unknown";

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
    if( version_is_greater_equal( version:maxVer, test_version:"5.2.6002.22509" ) ) {
      flag = TRUE;
    } else {
      fix = ">= 5.2.6002.22509";
    }
  }

  else if( hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3 ) > 0 ) {
    if( version_is_greater_equal( version:maxVer, test_version:"5.2.6002.22507" ) ) {
      flag = TRUE;
    } else {
      fix = ">= 5.2.6002.22507";
    }
  }

  else if( hotfix_check_sp( winVista:3, win2008:3 ) > 0 ) {
    SP = get_kb_item( "SMB/WinVista/ServicePack" );
    if( ! SP ) {
      SP = get_kb_item( "SMB/Win2008/ServicePack" );
    }

    if( "Service Pack 1" >< SP ) {
      if( version_in_range( version:maxVer, test_version:"5.2.6001.18551", test_version2:"5.2.6001.21999" ) ||
          version_is_greater_equal( version:maxVer, test_version:"5.2.6001.22791" ) ||
          version_in_range( version:maxVer, test_version:"6.0.6001.18551", test_version2:"6.0.6001.21999" ) ||
          version_is_greater_equal( version:maxVer, test_version:"6.0.6001.22791" ) ) {
        flag = TRUE;
      } else {
        fix = ">= 5.2.6001.22791 or >= 6.0.6001.22791";
      }
    }

    if( "Service Pack 2" >< SP ) {
      if( version_in_range( version:maxVer, test_version:"5.2.6002.18342", test_version2:"5.2.6002.21999" ) ||
          version_is_greater_equal( version:maxVer, test_version:"5.2.6002.22519" ) ||
          version_in_range( version:maxVer, test_version:"6.0.6002.18342", test_version2:"6.0.6002.21999" ) ||
          version_is_greater_equal( version:maxVer, test_version:"6.0.6002.22519" ) ) {
        flag = TRUE;
      } else {
        fix = ">= 5.2.6002.22519 or >= 6.0.6002.22519";
      }
    }
  }
}

if( ! flag ) {
  report = report_fixed_ver( file_version:maxVer, file_checked:maxPath, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
