# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103621");
  script_version("2025-03-28T15:41:52+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-28 15:41:52 +0000 (Fri, 28 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-12-11 10:59:09 +0200 (Tue, 11 Dec 2012)");
  script_name("Windows Version Detection (SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"SMB login-based detection of the installed Windows version.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("smb_nt.inc");

SCRIPT_DESC = "Windows Version Detection (SMB Login)";
banner_type = "Registry access via SMB";

winVal = get_kb_item( "SMB/WindowsVersion" );
if( ! winVal ) exit( 0 );

winName = get_kb_item( "SMB/WindowsName" );
csdVer  = get_kb_item( "SMB/CSDVersion" );
arch    = get_kb_item( "SMB/Windows/Arch" );
build   = get_kb_item( "SMB/WindowsBuild" );

if( isnull( csdVer ) ) {
  csdVer = "";
} else {
  csdVer = eregmatch( pattern:"Service Pack [0-9]+", string:csdVer );
  if( ! isnull( csdVer[0] ) ) csdVer = csdVer[0];
}

function register_win_version( cpe_base, win_vers, servpack, os_name, os_edition, os_branch, is64bit ) {

  local_var cpe_base, win_vers, servpack, os_name, os_edition, os_branch, is64bit;
  local_var cpe;

  servpack = ereg_replace( string:servpack, pattern:"Service Pack ", replace:"sp", icase:TRUE );

  if( ! isnull( servpack ) && strlen( servpack ) > 0 ) {

    if( ! win_vers )
      win_vers = "-";

    cpe = cpe_base + ":" + win_vers + ":" + servpack;
    if( is64bit && os_edition )
      cpe += ":" + os_edition + "_x64";
    else if( is64bit )
      cpe += ":x64";

  } else if( ! isnull( win_vers ) && strlen( win_vers ) > 0 ) {
    cpe = cpe_base + ":" + win_vers;
    if( os_edition && os_branch ) {
      cpe += ":" + os_branch + ":" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_edition ) {
      cpe += ":-:" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_branch ) {
      cpe += ":" + os_branch;
      if( is64bit )
        cpe += ":x64";
    } else if( is64bit ) {
      cpe += ":-:x64";
    }
  } else {
    cpe = cpe_base;
    if( os_edition && os_branch ) {
      cpe += ":-:" + os_branch + ":" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_edition ) {
      cpe += ":-:-:" + os_edition;
      if( is64bit )
        cpe += "_x64";
    } else if( os_branch ) {
      cpe += ":-:" + os_branch;
      if( is64bit )
        cpe += ":x64";
    } else if( is64bit ) {
      cpe += ":-:-:x64";
    }
  }

  # nb: Only a special handling if "win_vers" wasn't passed.
  if( win_vers == "-" )
    win_vers = "";

  os_register_and_report( os:os_name, version:win_vers, cpe:cpe, full_cpe:TRUE, banner_type:banner_type, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 ); # We don't need to continue here after the first match
}

if( winVal == "4.0" ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_nt", win_vers:"4.0", servpack:csdVer, os_name:winName );
}

if( winVal == "5.0" && "Microsoft Windows 2000" >< winName ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_2000", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "5.1" && "Microsoft Windows XP" >< winName ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_xp", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "5.2" && "Microsoft Windows XP" >< winName && "x64" >< arch ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_xp", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
}

if( winVal == "5.2" && "Microsoft Windows Server 2003" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2003", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2003", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.0" && "Windows Vista" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_vista", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_vista", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.0" && "Windows Server (R) 2008" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.1" && "Windows 7" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_7", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_7", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.1" && "Windows Server 2008 R2" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"r2", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2008", win_vers:"r2", servpack:csdVer, os_name:winName );
}

if( winVal == "6.2" && "Windows Server 2012" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.2" && "Windows 8" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows Server 2012 R2" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"r2", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2012", win_vers:"r2", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows 8.1" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8.1", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_8.1", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows Embedded 8.1" >< winName ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_embedded_8.1", win_vers:"", servpack:csdVer, os_name:winName );
} else if( ( "Windows Embedded" >< winName ) ) {
  register_win_version( cpe_base:"cpe:/o:microsoft:windows_embedded", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows 10" >< winName && build < "22000" ) {

  vers = "";
  os_branch = "";
  os_edition = "";
  if( ver = get_version_from_build( string:build, win_name:"win10" ) )
    vers = tolower( ver );

  if( "LTSB" >< winName )
    os_branch = "ltsb";
  else if( "LTSC" >< winName )
    os_branch = "ltsc";
  else
    os_branch = "cb";

  if( "Enterprise" >< winName )
    os_edition = "enterprise";
  else if( "Education" >< winName )
    os_edition = "education";
  else if( "Home" >< winName )
    os_edition = "home";
  else if( "Pro" >< winName )
    os_edition = "pro";
  else
    os_edition += "unknown_edition";

  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_10", win_vers:vers, servpack:csdVer, os_name:winName, os_branch:os_branch, os_edition:os_edition, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_10", win_vers:vers, servpack:csdVer, os_name:winName, os_branch:os_branch, os_edition:os_edition );
}

if( winVal == "6.3" && "Windows Server 2016" >< winName ) {
  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2016", win_vers:"", servpack:csdVer, os_name:winName, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2016", win_vers:"", servpack:csdVer, os_name:winName );
}

if( winVal == "6.3" && "Windows Server 2019" >< winName ) {

  vers = "";
  os_edition = "";
  if( ver = get_version_from_build( string:build, win_name:"win10" ) )
    vers = tolower( ver );

  if( "Datacenter" >< winName )
    os_edition = "datacenter";
  else if( "Standard" >< winName )
    os_edition = "standard";
  else
    os_edition += "unknown_edition";

  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2019", win_vers:vers, servpack:csdVer, os_name:winName, os_edition:os_edition, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2019", win_vers:vers, servpack:csdVer, os_name:winName, os_edition:os_edition );
}

if( winVal == "6.3" && "Windows Server 2022" >< winName ) {

  vers = "";
  os_edition = "";

  if( "Datacenter" >< winName )
    os_edition = "datacenter";
  else if( "Standard" >< winName )
    os_edition = "standard";
  else if( "Essentials" >< winName )
    os_edition = "essentials";
  else if( "Azure Datacenter" >< winName )
    os_edition = "azure_datacenter";
  else
    os_edition += "unknown_edition";

  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2022", win_vers:vers, servpack:csdVer, os_name:winName, os_edition:os_edition, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2022", win_vers:vers, servpack:csdVer, os_name:winName, os_edition:os_edition );
}

if( winVal == "6.3" && "Windows Server 2025" >< winName ) {

  vers = "";
  os_edition = "";

  if( "Datacenter" >< winName )
    os_edition = "datacenter";
  else if( "Standard" >< winName )
    os_edition = "standard";
  else if( "Essentials" >< winName )
    os_edition = "essentials";
  else if( "Azure Datacenter" >< winName )
    os_edition = "azure_datacenter";
  else
    os_edition += "unknown_edition";

  if( "x64" >< arch )
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2025", win_vers:vers, servpack:csdVer, os_name:winName, os_edition:os_edition, is64bit:TRUE );
  else
    register_win_version( cpe_base:"cpe:/o:microsoft:windows_server_2025", win_vers:vers, servpack:csdVer, os_name:winName, os_edition:os_edition );
}

# nb: winName still contains "Windows 10" on Windows 11 (because given like this in the registry)
# but we can detect Windows 11 based on the build.
if( winVal == "6.3" && "Windows 10" >< winName && build >= "22000" ) {

  cpe = "cpe:/o:microsoft:windows_11";
  version = "unknown";

  if( vers = get_version_from_build( string:build, win_name:"win11" ) ) {
    cpe += ":" + tolower(vers);
    version = vers;
  } else {
    cpe += "::";
  }

  if( "LTSB" >< winName )
    cpe += ":ltsb";
  else if( "LTSC" >< winName )
    cpe += ":ltsc";
  else
    cpe += ":cb";

  if( "Enterprise" >< winName )
    edition = "enterprise";
  else if( "Home" >< winName )
    edition = "home";
  else if( "Pro Education" >< winName )
    edition = "pro_education";
  else if( "Pro for Workstations" >< winName )
    edition = "pro_for_workstations";
  # nb: "Pro" and "Education" needs to be after the two above
  else if( "Education" >< winName )
    edition = "education";
  else if( "Pro" >< winName )
    edition = "pro";
  else if( "SE" >< winName )
    edition = "se";
  else
    edition = "unknown_edition";

  cpe += ":" + edition;

  # nb: winName still contains "Windows 10" on Windows 11 (because given like this in the registry)
  # so we need to rewrite this here before passing the info to the user.
  winName = str_replace( string:winName, find:"Windows 10", replace:"Windows 11" );

  # nb: Microsoft's Windows 11 operating system is 64-bit supported only
  cpe += "_x64";

  # nb: Not using register_win_version() here as we already have build the full CPE etc.
  os_register_and_report( os:winName, version:version, cpe:cpe, full_cpe:TRUE, banner_type:banner_type, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

## Fallback if none of the above is matching, also report as "unknown" OS.
## Some embedded XP versions are only providing a winVal but not a winName. Avoid a unknown reporting for those and just register the OS
if( winVal && winName ) {
  os_register_unknown_banner( banner:"winVal = " + winVal + ", winName = " + winName + ", arch = " + arch, banner_type_name:banner_type, banner_type_short:"smb_win_banner" );
}

register_win_version( cpe_base:"cpe:/o:microsoft:windows", win_vers:"", servpack:csdVer, os_name:winName );

#nb: If updating / adding OS detection here please also update gb_windows_cpe_detect.nasl and smb_reg_service_pack.nasl

exit( 0 );
