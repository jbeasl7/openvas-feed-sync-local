# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900332");
  script_version("2025-06-04T05:40:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Symantec Products Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of Symantec products.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_symantec_endpoint_protection_smb_login_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  script_exclude_keys("keys/is_gef");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
  key_list2 = make_list( "SOFTWARE\Symantec\Symantec Endpoint Protection\SEPM" );
  sepm_key = "SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion";
}

else if( "x64" >< os_arch ) {
  key_list =  make_list( "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
  key_list2 = make_list( "SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\SEPM" );
  sepm_key = "SOFTWARE\WOW6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion";
}

if( ! key_list )
  exit( 0 );

foreach symkey( key_list ) {
  foreach item( registry_enum_keys( key:symkey ) ) {
    symantecName = registry_get_sz( key:symkey + item, item:"DisplayName" );

    if( "Norton AntiVirus" >< symantecName ) {
      navVer = registry_get_sz( key:symkey + item, item:"DisplayVersion" );
      if( navVer ) {
        set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE );
        set_kb_item( name:"Symantec/Norton-AV/Ver", value:navVer );

        navPath = registry_get_sz( key:symkey + item, item:"InstallLocation" );
        if( ! navPath )
          navPath = "Could not find the install Location from registry";

        register_and_report_cpe( app:symantecName, ver:navVer, concluded:navVer, base:"cpe:/a:symantec:norton_antivirus:", expr:"^([0-9.]+)", insloc:navPath, regPort:0, regService:"smb-login" );
      }
    }

    if( "Norton Internet Security" >< symantecName ) {
      nisVer = registry_get_sz( key:symkey + item, item:"DisplayVersion" );
      if( nisVer ) {
        set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE );
        set_kb_item( name:"Norton/InetSec/Ver", value:nisVer );

        nisPath = registry_get_sz( key:symkey + item, item:"InstallLocation" );
        if( ! nisPath )
          nisPath = "Could not find the install Location from registry";

        register_and_report_cpe( app:symantecName, ver:nisVer, concluded:nisVer, base:"cpe:/a:symantec:norton_internet_security:", expr:"^([0-9.]+)", insloc:nisPath, regPort:0, regService:"smb-login" );
      }
    }

    if( "Symantec pcAnywhere" >< symantecName ) {
      pcawVer = registry_get_sz( key:symkey + item, item:"DisplayVersion" );
      if( pcawVer ) {
        set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE );
        set_kb_item( name:"Symantec/pcAnywhere/Ver", value:pcawVer );

        pcawPath = registry_get_sz( key:symkey + item, item:"InstallLocation" );
        if( ! pcawPath )
          pcawPath = "Could not find the install Location from registry";

        register_and_report_cpe( app:symantecName, ver:pcawVer, concluded:pcawVer, base:"cpe:/a:symantec:pcanywhere:", expr:"^([0-9.]+)", insloc:pcawPath, regPort:0, regService:"smb-login" );
      }
    }

    if( "Enterprise Security Manager" >< symantecName ) {
      esmVer = registry_get_sz( key:symkey + item, item:"DisplayVersion" );
      if( esmVer ) {
        set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE );
        set_kb_item( name:"Symantec/ESM/Ver", value:esmVer );
        set_kb_item( name:"Symantec/ESM/Component", value:symantecName );

        esmPath = registry_get_sz( key:symkey + item, item:"InstallLocation" );
        if( ! esmPath )
          esmPath = "Could not find the install Location from registry";

        set_kb_item( name:"Symantec/ESM/Path", value:esmPath );
        register_and_report_cpe( app:symantecName, ver:esmVer, concluded:esmVer, base:"cpe:/a:symantec:enterprise_security_manager:", expr:"^([0-9.]+)", insloc:esmPath, regPort:0, regService:"smb-login" );
      }
    }

    # nb: Symantec AntiVirus Corporate Edition, this product is discontinued.
    if( "Symantec AntiVirus" >< symantecName ) {
      savceVer = registry_get_sz( key:symkey + item, item:"DisplayVersion" );
      if( savceVer ) {
        set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE );
        set_kb_item( name:"Symantec/SAVCE/Ver", value:savceVer );

        savcePath = registry_get_sz( key:symkey + item, item:"InstallLocation" );
        if( ! savcePath )
          savcePath = "Could not find the install Location from registry";

        register_and_report_cpe( app:symantecName, ver:savceVer, concluded:savceVer, base:"cpe:/a:symantec:antivirus:", expr:"^([0-9.]+)", insloc:savcePath, regPort:0, regService:"smb-login" );
      }
    }

    # nb: IMManager - this product is discontinued
    if( "IMManager" >< symantecName ) {
      imPath = registry_get_sz( key:symkey + item, item:"InstallSource" );
      if( imPath ) {
        imPath = imPath - "\temp";
        imVer = fetch_file_version( sysPath:imPath, file_name:"IMLogicAdminService.exe" );

        if( imVer ) {
          set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE );
          set_kb_item( name:"Symantec/IM/Manager", value:imVer );
          register_and_report_cpe( app:symantecName, ver:imVer, concluded:imVer, base:"cpe:/a:symantec:im_manager:", expr:"^([0-9.]+)", insloc:imPath, regPort:0, regService:"smb-login" );
        }
      }
    }
  }
}

# nb: No need to run this part of the detection at all because the new gsf/gb_symantec_endpoint_protection_smb_login_detect.nasl should run instead
if( get_kb_item( "keys/is_gef" ) )
  exit( 0 );

foreach symkey( key_list2 ) {
  if( registry_key_exists( key:symkey ) ) {
    nisVer = registry_get_sz( key:symkey, item:"Version" );
    if( nisVer ) {
      set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", agentvalue:TRUE );
      set_kb_item( name:"Symantec/Endpoint/Protection", value:nisVer );

      nisPath = registry_get_sz( key:symkey + item, item:"TargetDir" );
      if( nisPath )
        nisPath = "Could not find the install Location from registry";

      # nb: ProductType sepsb: (Symantec Endpoint Protection Small Business)
      nisType = registry_get_sz( key:symkey, item:"ProductType" );
      if( nisType && "sepsb" >< nisType ) {
        set_kb_item( name:"Symantec/SEP/SmallBusiness", value:nisType );
        base = "cpe:/a:symantec:endpoint_protection:" + nisVer + ":small_business";
      } else {
        base = "cpe:/a:symantec:endpoint_protection:";
      }
      register_and_report_cpe( app:"Symantec Endpoint Protection", ver:nisVer, concluded:nisVer, base:base, expr:"^([0-9.]+)", insloc:nisPath, regPort:0, regService:"smb-login" );
    }
  }
}

# nb: For some cases above the detection does not work
# [HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion]
# "PRODUCTVERSION"="14.2.4814.1101"
#
# [HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Symantec\Symantec Endpoint Protection\CurrentVersion\Common Client]
# "CCROOT"="C:\\Program Files (x86)\\Symantec\\Symantec Endpoint Protection\\14.2.4814.1101.105\\bin"

if( registry_key_exists( key:sepm_key ) ) {
  nisVer = registry_get_sz( key:sepm_key, item:"PRODUCTVERSION" );

  key = sepm_key + "\Common Client";
  if( registry_key_exists( key:key ) ) {
    sepm_path = registry_get_sz( key:key, item:"CCROOT" );
    if( sepm_path ) {
      nisPath = eregmatch( pattern:"(.*Symantec Endpoint Protection)", string:sepm_path );
      if( ! isnull( nisPath[1] ) )
        nisPath = nisPath[1];

      if( ! nisVer ){
        version = eregmatch( pattern:"Symantec Endpoint Protection.*\\([0-9.]+)", string:sepm_path );
        if( ! isnull( version[1] ) )
          nisVer = version[1];
      }
    }
  }

  if( nisVer ) {
    set_kb_item( name:"Symantec_or_Norton/Products/Win/Installed", value:TRUE );
    set_kb_item( name:"Symantec/Endpoint/Protection", value:nisVer );

    if( ! nisPath )
      nisPath = "Could not find the install Location from registry";

    register_and_report_cpe( app:"Symantec Endpoint Protection", ver:nisVer, concluded:nisVer, base:"cpe:/a:symantec:endpoint_protection:", expr:"^([0-9.]+)", insloc:nisPath, regPort:0, regService:"smb-login" );
  }
}

exit( 0 );
