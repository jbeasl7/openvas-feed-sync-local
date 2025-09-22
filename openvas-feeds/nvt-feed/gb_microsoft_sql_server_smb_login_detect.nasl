# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102096");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-04-18 08:09:53 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Microsoft SQL (MSSQL) Server Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of Microsoft SQL (MSSQL) Server for
  Windows.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("http_func.inc");

if( ! os_arch = get_kb_item( "SMB/Windows/Arch" ) )
  exit( 0 );

key_list_named_instance = make_list();
# n.b. Gathering the list of installed instances as multiple instance e.g. SQL Server 2019 and SQL Server 2022
# on the same system are possible.
# This registry entry is present since SQL Server 2005
item_list = registry_enum_values( key:"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" );
item_list_wow = registry_enum_values( key:"SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL" );

foreach item ( item_list ) {
  if ( item == "" ) continue;
  key = registry_get_sz( key:"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL", item:item );
  key = "SOFTWARE\Microsoft\Microsoft SQL Server\" + key + "\Setup";
  key_list_named_instance = make_list( key_list_named_instance, key );
}

foreach item ( item_list_wow ) {
  if ( item == "" ) continue;
  key = registry_get_sz( key:"SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL", item:item );
  key = "SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\" + key + "\Setup";
  key_list_named_instance = make_list( key_list_named_instance, key );
}

# n.b Covering SQL Server 2000 and older instances with different registry structure
if ( max_index(key_list_named_instance) == 0 ) {

  key_list_named_instance_old = make_list();

  # n.b. Gathering the list of installed instances as multiple instances are possible
  item_list = registry_get_sz( key:"SOFTWARE\Microsoft\Microsoft SQL Server\", item:"InstalledInstances", multi_sz:TRUE );
  item_list_wow = registry_get_sz( key:"SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\", item:"InstalledInstances", multi_sz:TRUE );

  if ( item_list )
    item_list = split( str_replace( string:item_list, find:'\n', replace:"," ), sep:",", keep:FALSE );

  if ( item_list_wow )
    item_list_wow = split( str_replace( string:item_list_wow, find:'\n', replace:"," ), sep:",", keep:FALSE );

  foreach item ( item_list ) {
    if ( item == "" ) continue;
    # n.b. At least Microsoft SQL Server 2000 saves the information about the default instance in a different location
    if ( item == "MSSQLSERVER" ) {
      key = "SOFTWARE\Microsoft\" + item + "\Setup";
      key_list_named_instance_old = make_list( key_list_named_instance_old, key );
    } else {
      key = "SOFTWARE\Microsoft\Microsoft SQL Server\" + item + "\Setup";
      key_list_named_instance_old = make_list( key_list_named_instance_old, key );
    }
  }

  foreach item ( item_list_wow ) {
    if ( item == "" ) continue;
    # n.b. At least Microsoft SQL Server 2000 saves the information about the default instance in a different location
    if ( item == "MSSQLSERVER" ) {
      key = "SOFTWARE\WOW6432Node\Microsoft\" + item + "\Setup";
      key_list_named_instance_old = make_list( key_list_named_instance_old, key );
    } else {
      key = "SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\" + item + "\Setup";
      key_list_named_instance_old = make_list( key_list_named_instance_old, key );
    }
  }
}


if( isnull( key_list_named_instance_old ) && isnull( key_list_named_instance ) )
  exit( 0 );

foreach key( key_list_named_instance_old ) {

  sql_path = registry_get_sz( key:key, item:"SQLPath" ) + "\Binn";

  concluded  = '\n  FilePath:        ' + sql_path + "\sqlservr.exe";
  location = "unknown";
  version = "unknown";

  # n.b Returns the version like this 8.0.1.94 so we manipulate it to fit the right scheme
  vers = fetch_product_version( sysPath:sql_path, file_name:"sqlservr.exe" );
  vers_length = strlen( vers );
  vers = substr( vers, 0, 4 ) + substr( vers, 6, vers_length );

  if ( vers ) {
    location = sql_path;
    version = vers;
    concluded += '\n  ProductVersion:  ' + vers;
  }

  set_kb_item( name:"microsoft/sqlserver/detected", value:TRUE );
  set_kb_item( name:"microsoft/sqlserver/smb-login/detected", value:TRUE );
  set_kb_item( name:"microsoft/sqlserver/smb-login/0/installs",
               value:"0#---#" + "unknown#---#" + location + "#---#" + version + "#---#" + concluded );
}

foreach key( key_list_named_instance ) {

  sql_path = registry_get_sz( key:key, item:"SQLBinRoot" );

  concluded  = '\n  FilePath:        ' + sql_path + "\sqlservr.exe";
  location = "unknown";
  version = "unknown";

  if ( vers = fetch_product_version( sysPath:sql_path, file_name:"sqlservr.exe" ) ) {
    location = sql_path;
    version = vers;
    concluded += '\n  ProductVersion:  ' + vers;
  }

  set_kb_item( name:"microsoft/sqlserver/detected", value:TRUE );
  set_kb_item( name:"microsoft/sqlserver/smb-login/detected", value:TRUE );
  set_kb_item( name:"microsoft/sqlserver/smb-login/0/installs",
               value:"0#---#" + "unknown#---#" + location + "#---#" + version + "#---#" + concluded );
}

exit( 0 );
