# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800257");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("OpenSSL Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login-based detection of OpenSSL.");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("list_array_func.inc");
include("policy_functions.inc");
include("powershell_func.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

port = kb_smb_transport();

file_list = powershell_wmi_file_search_query( file_name:"openssl", file_extension:"exe" );

if( ! file_list || ! is_array( file_list ) )
  exit( 0 );

foreach file( file_list ) {

  if( ! file || "\openssl.exe" >!< tolower( file ) )
    continue;

  found = TRUE;
  version = "unknown";
  location = "unknown";
  concluded = ""; # nb: To reset the value

  split = split( file, sep:"\" );
  count = max_index( split ) - 1;
  file_name = split[count];
  location = ereg_replace( string:file, pattern:split[max_index( split ) - 1], replace:"" );

  concluded = "File at " + file;

  value = powershell_fetch_product_version( sysPath:location, file_name:file_name );
  if( value ) {
    version = value;
    concluded += '\nProduct version: ' + version  + " fetched from the executable with PowerShell.";
  }

  set_kb_item( name:"openssl/smb-login/" + port + "/installs", value:"0#---#" + location + "#---#" + version + "#---#" + concluded );
}

if( found ) {
  set_kb_item( name:"openssl/detected", value:TRUE );
  set_kb_item( name:"openssl_or_gnutls/detected", value:TRUE );
  set_kb_item( name:"openssl/smb-login/detected", value:TRUE );
}

exit( 0 );
