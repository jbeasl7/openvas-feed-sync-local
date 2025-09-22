# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108442");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-05-16 07:49:52 +0200 (Wed, 16 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Authenticated Scan / LSC Info Consolidation (Windows SMB Login)");
  # nb: Needs to run at the end of the scan because of the required info only available in this
  # phase...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_registry_access.nasl", "gb_wmi_access.nasl", "smb_reg_service_pack.nasl",
                      "lsc_options.nasl", "logins.nasl", "smb_login.nasl",
                      "smb_windows_build.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_exclude_keys("SMB/samba");

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-24.10/en/scanning.html#requirements-on-target-systems-with-microsoft-windows");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#requirements-on-target-systems-with-microsoft-windows");

  script_tag(name:"summary", value:"Consolidation and reporting of various technical information
  about authenticated scans / local security checks (LSC) via SMB for Windows targets.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");
include("misc_func.inc");
include("list_array_func.inc");

_kb_login = kb_smb_login();
# The user hasn't filled out a login name so no need to
# report the infos below if no LSC scan was requested.
if( ! strlen( _kb_login ) > 0 )
  exit( 0 );

if( kb_smb_is_samba() )
  exit( 0 );

empty_text = "Empty/None";

# nb: Special handling for Windows 11 as it still reports itself as Window 10...
is_win11 = 0;

info_array = make_array();
# nb: key is the KB item, value the description used in the report
# The order doesn't matter, this will be sorted later in text_format_table()
kb_array = make_array( "WMI/access_successful", "Access via WMI possible",
                       "Tools/Present/wmi", "Extended WMI support available via openvas-smb module",
                       "Tools/Present/smb", "Extended SMB support available via openvas-smb module",
                       "win/lsc/search_portable_apps", "Enable Detection of Portable Apps on Windows",
                       "win/lsc/disable_win_cmd_exec", "Disable the usage of win_cmd_exec for remote commands on Windows",
                       "win/lsc/disable_wmi_search", "Disable file search via WMI on Windows",
                       "SMB/registry_access", "Access to the registry possible",
                       "SMB/WindowsVersion", "Version number of the OS",
                       "SMB/WindowsVersionString", "Version string of the OS",
                       "SMB/WindowsBuild", "Build number of the OS",
                       "SMB/WindowsName", "Product name of the OS",
                       "SMB/Windows/Arch", "Architecture of the OS",
                       "SMB/workgroup", "Workgroup of the SMB server",
                       "SMB/dont_send_ntlmv1", "Only use NTLMv2",
                       "SMB/dont_send_in_cleartext", "Never send SMB credentials in clear text",
                       "SMB/registry_access_missing_permissions", "Missing access permissions to the registry",
                       "SMB/CSDVersion", "Name of the most recent service pack installed",
                       "Microsoft/Windows/FullBuild", "Full Windows build number",
                       "Microsoft/Windows/FullName", "Full Windows name" );

foreach kb_item( keys( kb_array ) ) {
  if( kb = get_kb_item( kb_item ) ) {
    if( kb == TRUE )
      kb = "TRUE";
    info_array[kb_array[kb_item] + " (" + kb_item + ")"] = kb;
    if( kb_item == "SMB/WindowsBuild" && kb >= "22000" )
      is_win11++;
    if( kb_item == "SMB/WindowsName" && "Windows 10" >< kb )
      is_win11++;
  } else {
    if( kb_item == "SMB/CSDVersion" || kb_item == "SMB/workgroup" ||
        kb_item == "SMB/Windows/Arch" || kb_item == "SMB/WindowsBuild" ||
        kb_item == "SMB/WindowsName" || kb_item == "SMB/WindowsVersion" ||
        kb_item == "Microsoft/Windows/FullBuild" || kb_item == "Microsoft/Windows/FullName" ) {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = empty_text;
    } else {
      info_array[kb_array[kb_item] + " (" + kb_item + ")"] = "FALSE";
    }
  }
}

if( ! domain = kb_smb_domain() )
  domain = empty_text;

if( ! transport = kb_smb_transport() )
  transport = empty_text;
else
  transport += "/tcp";

if( ! name = kb_smb_name() )
  name = empty_text;

if( ! sysroot = smb_get_systemroot() )
  sysroot = empty_text;

if( ! sys32root = smb_get_system32root() )
  sys32root = empty_text;

if( ! hostname = kb_smb_hostname() )
  hostname = empty_text;

if( ! kdc = kb_smb_kdc() )
  kdc = empty_text;

info_array["Port configured for authenticated scans (kb_smb_transport())"] = transport;
info_array["User used for authenticated scans (kb_smb_login())"] = _kb_login;
info_array["Domain used for authenticated scans (kb_smb_domain())"] = domain;
info_array["SMB name used for authenticated scans (kb_smb_name())"] = name;
info_array["KDC used for authenticated scans (kb_smb_kdc())"] = kdc;
info_array["Hostname used for authenticated scans (kb_smb_hostname())"] = hostname;
info_array["Path to the OS SystemRoot (smb_get_systemroot())"] = sysroot;
info_array["Path to the OS SystemRoot for 32bit (smb_get_system32root())"] = sys32root;

if( defined_func( "krb5_gss_init" ) )
  info_array["Kerberos support available (krb5_gss_init() scanner function available)"] = "TRUE";
else
  info_array["Kerberos support available (krb5_gss_init() scanner function available)"] = "FALSE";

success = get_kb_item( "login/SMB/success" );
success_port = get_kb_item( "login/SMB/success/port" );
success_reason = get_kb_item( "login/SMB/success/reason" );
if( success ) {

  info_array["Login via SMB successful (login/SMB/success)"] = "TRUE";

  if( success_port )
    info_array["Port used for the successful login via SMB"] = success_port + "/tcp";

  if( success_reason )
    info_array["Message for the successful login via SMB"] = success_reason;

} else {
  info_array["Login via SMB successful (login/SMB/success)"] = "FALSE";
}

failed = get_kb_item( "login/SMB/failed" );
failed_port = get_kb_item( "login/SMB/failed/port" );
failed_reason = get_kb_item( "login/SMB/failed/reason" );
if( failed ) {

  info_array["Login via SMB failed (login/SMB/failed)"] = "TRUE";

  if( failed_port )
    info_array["Port used for the failed login via SMB"] = failed_port + "/tcp";

  if( failed_reason )
    info_array["Message for the failed login via SMB"] = failed_reason;

} else {
  info_array["Login via SMB failed (login/SMB/failed)"] = "FALSE";
}

if( krb5_is_failure() ) {
  krb5_error_code = get_kb_item( "login/SMB/krb5_error_code" );
  if( krb5_error_code )
    info_array["Kerberos error code (krb5_error_code_to_string())"] = krb5_error_code;
}

report = text_format_table( array:info_array, columnheader:make_list( "Description (Knowledge base entry)", "Value/Content" ) );

if( ! get_kb_item( "SMB/registry_access" ) ) {
  if( error = get_kb_item( "SMB/registry_access/error" ) )
    report += '\n\n' + error;
}

miss_perm = get_kb_item( "SMB/registry_access_missing_permissions" );
if( miss_perm ) {
  miss_report = get_kb_item( "SMB/registry_access_missing_permissions/report" );
  if( ! error )
    report += '\n';
  if( miss_report )
    report += '\n' + miss_report;
}

if( is_win11 > 1 )
  report += '\n\nNote/Important: Windows 11 still reports itself as Windows 10 in the registry so it is expected that "SMB/WindowsName" contains the Windows 10 string.';

log_message( port:0, data:report );
exit( 0 );
