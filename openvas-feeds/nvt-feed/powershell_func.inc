# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var __win_cmd_exec_disabled;

# @brief Returns the info if "Disable the usage of win_cmd_exec for remote commands on Windows" was enabled
#        (win/lsc/disable_win_cmd_exec of lsc_options.nasl) within the scan config.
#        To avoid querying the KB for the same info again it will be cached within an internal variable.
#
# @return TRUE if usage of win_cmd_exec was disabled, FALSE otherwise.
#
function is_win_cmd_exec_disabled() {

  local_var is_win_cmd_exec_disabled;

  # nb: __win_cmd_exec_disabled is a global var
  if( ! isnull( __win_cmd_exec_disabled ) ) {
    is_win_cmd_exec_disabled = __win_cmd_exec_disabled;
  } else {
    is_win_cmd_exec_disabled = get_kb_item( "win/lsc/disable_wmi_search" );
    if( is_win_cmd_exec_disabled )
      __win_cmd_exec_disabled = TRUE;
    else
      __win_cmd_exec_disabled = FALSE;
    is_win_cmd_exec_disabled = __win_cmd_exec_disabled;
  }
  return is_win_cmd_exec_disabled;
}

# @brief Performs a powershell command against a Windows host
#
# @param cmd The powershell command to run
#
# @return A string with the command result from the Windows host, NULL if no result was returned or
#         not all mandatory function parameters have been given
#
function powershell_cmd( cmd ) {

  local_var cmd;
  local_var infos, result;


  if( ! defined_func( "win_cmd_exec" ) )
    return;

  if( ! infos = kb_smb_wmi_connectinfo() )
    return;

  if( ! cmd ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#powershell_cmd" );
    return;
  }

  cmd = 'powershell -Command " & {' + cmd + '}"';

  if( ! get_kb_item( "login/SMB/kerberos/success" ) ) {
    result = win_cmd_exec( cmd:cmd, password:infos["password"], username:infos["username_wincmd"] );
  } else {
    result = win_cmd_exec( cmd:cmd, password:infos["password"], username:infos["username_wincmd"],
                           realm:infos["domain"], kdc:infos["kdc"], host:infos["hostname"] );
  }

  if( ! result = chomp( result ) )
    return;

  if( result =~ "fullyqualifiederrorid\s*:\s*[a-zA-Z]+" || result =~ "categoryinfo\s*:\s*[a-zA-Z]+" )
    return;

  # Get rid of wmiexec.py prefix and any trailing / leading whitespaces
  result = ereg_replace( string:result, pattern:"(Impacket .+ dialect used)", replace:"" );
  result = ereg_replace( string:chomp( result ), pattern:"^\s+", replace:"" );
  if( result )
    return( result );

  return;
}

# @brief This function will get the version details of a given file using the product version method and powershell.
#
# @param sysPath          The path to the file. Mandatory.
# @param file_name        The name of the file. Mandatory.
# @param use_file_version Boolean flag which, when true, would lead to retrieving FileVersion instead of ProductVersion. Optional
#
# @return The version of the file, FALSE if not all mandatory parameters were passed or no version was found.
#
function powershell_fetch_product_version( sysPath, file_name, use_file_version ) {

  local_var sysPath, file_name, use_file_version;
  local_var version_info_field, kb_proxy_file, kb_proxy, get_ver_cmd, sysVer;

  if( ! sysPath ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#sysPath#-#powershell_fetch_product_version" );
    return FALSE;
  }

  if( ! file_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#powershell_fetch_product_version" );
    return FALSE;
  }

  version_info_field = "ProductVersion";
  if( use_file_version )
    version_info_field = "FileVersion";

  file_name = tolower( file_name );
  sysPath = tolower( sysPath );

  kb_proxy_file = "SMB//powershell_fetch_product_version//" + sysPath + "//" + file_name + "//" + version_info_field;

  kb_proxy = get_kb_item( kb_proxy_file );
  if( ! isnull( kb_proxy ) || kb_proxy ) {
    if( kb_proxy == "unknown" )
      return FALSE;
    else
      return kb_proxy;
  }

  get_ver_cmd = '(ls \\"' + sysPath + "\" + file_name + '\\").VersionInfo | select ' + version_info_field + ' | ft -HideTableHeaders';
  sysVer = powershell_cmd( cmd:get_ver_cmd );

  if( sysVer )
    set_kb_item( name:kb_proxy_file, value:sysVer );

  return sysVer;
}

# @brief Performs a WMI/CIM based query against the target host using powershell provided functionalities
#
# @param query: The query to run, mutually exclusive with classname and properties
# @param classname: The specific classname to look for, can be used standalone
# @param class_args: Extra arguments to be used with the classname, if the case
# @param properties A single property or a list of comma separated properties to be returned for
#                   the given class, can only be used in combination with classname
# @param force_wmi_object Forces to use Get-WmiObject instead of Get-CimInstance
# @param as_list Formats the output in a list of the form property = value
#                Mutually exclusive with properties
#
# @return String with the query result from the windows target, NULL if no result was returned
#
function powershell_wmi_query( query, namespace, classname, class_args, properties, force_wmi_object, as_list ) {

  local_var query, namespace, classname, class_args, properties, force_wmi_object, as_list;
  local_var format_list, format_properties, cmd, result;

  if( force_wmi_object )
    cmd = "Get-WmiObject";
  else
    cmd = "Get-CimInstance";

  if( namespace )
    cmd += " -namespace '" + namespace + "'";

  format_list = " | ForEach-Object { $_.psobject.Properties | ForEach-Object { \" + '"$($_.Name) = $($_.Value)'+"\"+'"' + " } }";

  if( classname ) {
    cmd += " -ClassName " + classname;
    if( class_args )
      cmd += " " + class_args;

    if( properties ) {
      if("," >< properties ) {
        cmd += " | Select-Object " + properties + " | foreach-object {$_.";
        format_properties = ereg_replace(string:properties ,pattern:"," , replace:" + ';' + $_.");
        cmd += format_properties + " + ';'}";
      } else {
        cmd = "(" + cmd + ")." + properties;
      }
    } else if ( as_list ) {
      cmd += format_list;
    } else {
      cmd += " | Format-List -Property *";
    }
  } else if ( query ) {
    cmd += " -Query '" + query + "'";

    if( properties ) {
      if("," >< properties ) {
        cmd += " | Select-Object " + properties + " | foreach-object {$_.";
        format_properties = ereg_replace(string:properties ,pattern:"," , replace:" + ';' + $_.");
        cmd += format_properties + " + ';'}";
      } else {
        cmd = "(" + cmd + ")." + properties;
      }
    }else if ( as_list ){
      cmd += format_list;
    } else {
      cmd += " | Format-List -Property *";
    }
  }

  result = powershell_cmd( cmd:cmd );

  if( result )
    return( result );

  return;
}

# nb: This global variable will replace eventually the __wmi_file_search_disabled variable from wmi_file.inc
global_var __powershell_wmi_file_search_disabled;

# @brief Returns the info if "Disable file search via WMI on Windows" was enabled (win/lsc/disable_wmi_search of lsc_options.nasl)
#        within the scan config. To avoid querying the KB for the same info again it will be cached within an internal variable.
#
# @return TRUE if WMI file search was disabled, FALSE otherwise.
#
function wmi_is_file_search_disabled() {

  local_var is_file_search_disabled;

  # nb: __powershell_wmi_file_search_disabled is a global var
  if( ! isnull( __powershell_wmi_file_search_disabled ) ) {
    is_file_search_disabled = __powershell_wmi_file_search_disabled;
  } else {
    is_file_search_disabled = get_kb_item( "win/lsc/disable_wmi_search" );
    if( is_file_search_disabled )
      __powershell_wmi_file_search_disabled = TRUE;
    else
      __powershell_wmi_file_search_disabled = FALSE;

    is_file_search_disabled = __powershell_wmi_file_search_disabled;
  }
  return is_file_search_disabled;
}

# @brief Core function intended to be used by the other WMI search functions. It prepares the corresponding cache KB key for the given parameters.
#
# @param dir_path       The path to limit the query to (optional), Example: "\\Windows\\" (Without the drive letter and with the doubled trailing backslashes)
# @param dir_path_like  The path to limit the query to (optional) which is used in a LIKE statement, Example: "%windowssearchengine%"
# @param file_name      The file name to search for (mandatory, without the file extension), Example: "Safari"
# @param file_extension The file extension to limit the query to (optional), Example: "exe" (without a dot)
# @param function_name  The client function name, which will be used inside the KB key
#
# @return The filter part to be used for the WMI file search, or NULL if there is a problem with the parameters
#
function powershell_wmi_file_search_cache_key( dir_path, dir_path_like, file_name, file_extension, function_name ) {

  local_var dir_path, dir_path_like, file_name, file_extension, function_name;

  if( ! function_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#function_name#-#powershell_wmi_file_search_cache_key" );
    return NULL;
  }

  if( ! file_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#powershell_wmi_file_search_cache_key" );
    return NULL;
  }

  if( dir_path && file_name && file_extension ) {
    return "WMI/" + function_name + "/dir_path_file_name_file_extension/" + tolower( dir_path ) + "/" + tolower( file_name ) + "/" + tolower( file_extension );
  } else if( dir_path_like && file_name && file_extension ) {
    return "WMI/" + function_name + "/dir_path_like_file_name_file_extension/" + tolower( dir_path_like ) + "/" + tolower( file_name ) + "/" + tolower( file_extension );
  } else if( file_name && file_extension ) {
    return "WMI/" + function_name + "/file_name_file_extension/" + tolower( file_name ) + "/" + tolower( file_extension );
  } else {
    return "WMI/" + function_name + "/file_name/" + tolower( file_name );
  }
}

# @brief Core function intended to be used by the other WMI search functions.
#
# @param dir_path       The path to limit the query to (optional), Example: "\\Windows\\" (Without the drive letter and with the doubled trailing backslashes)
# @param dir_path_like  The path to limit the query to (optional) which is used in a LIKE statement, Example: "%windowssearchengine%"
# @param file_name      The file name to search for (mandatory, without the file extension), Example: "Safari"
# @param file_extension The file extension to limit the query to (optional), Example: "exe" (without a dot)
#
# @return The filter part to be used for the WMI file search, or NULL if there is a problem with the parameters
#
function powershell_wmi_file_search_construct_filter( dir_path, dir_path_like, file_name, file_extension ) {

  local_var dir_path, dir_path_like, file_name, file_extension;
  local_var query;

  if( ! file_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#powershell_wmi_file_search_construct_filter" );
    return NULL;
  }

  query = "-Filter \" + raw_string( 0x22 ) + "FileName = '" + file_name + "'";

  if( file_extension )
    query += " AND Extension = '" + file_extension + "'";

  if( dir_path )
    query += " AND Path = '" + dir_path + "'";
  else if( dir_path_like )
    query += " AND Path LIKE '" + dir_path_like + "'";

  query += '\\"';

  return query;
}

# @brief Performs a file search WMI query against the target host using powershell provided functionalities
#
# @param dir_path       The path to limit the query to (optional), Example: "\\Windows\\" (Without the drive letter and with the doubled trailing backslashes)
# @param dir_path_like  The path to limit the query to (optional) which is used in a LIKE statement, Example: "%windowssearchengine%"
# @param file_name      The file name to search for (mandatory, without the file extension), Example: "Safari"
# @param file_extension The file extension to limit the query to (optional), Example: "exe" (without a dot)
#
# @return A list of files matching the query, FALSE if no files exists matching the query or NULL
#         if not all required information are passed or the target system has denied the access
#
function powershell_wmi_file_search_query( dir_path, dir_path_like, file_name, file_extension ) {

  local_var dir_path, dir_path_like, file_name, file_extension;
  local_var kb_proxy_key, kb_proxy_list, query, query_res, _list, split_list, split_item;

  if( wmi_is_file_search_disabled() )
    return NULL;

  if( ! file_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#powershell_wmi_file_search_query" );
    return NULL;
  }

  if( dir_path && dir_path_like ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#dir_path and dir_path_like passed but only one of both can be used#-#powershell_wmi_file_search_query" );
    return NULL;
  }

  if( ! file_extension )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_extension#-#powershell_wmi_file_search_query" );

  if( ! dir_path )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dir_path#-#powershell_wmi_file_search_query" );

  kb_proxy_key = powershell_wmi_file_search_cache_key( dir_path:dir_path, dir_path_like:dir_path_like, file_name:file_name, file_extension:file_extension, function_name:"powershell_wmi_file_search_query" );

  kb_proxy_list = get_kb_list( kb_proxy_key );

  if( ! isnull( kb_proxy_list ) || kb_proxy_list )
    return kb_proxy_list;

  query = powershell_wmi_file_search_construct_filter( dir_path:dir_path, dir_path_like:dir_path_like, file_name:file_name, file_extension:file_extension );

  query_res = powershell_wmi_query( classname:"CIM_DataFile", class_args:query, properties:"Name", force_wmi_object:TRUE );

  if( ! query_res )
    return FALSE;

  _list = make_list();

  split_list = split( query_res, keep:FALSE );
  foreach split_item( split_list ) {
    set_kb_item( name:kb_proxy_key, value:split_item );
    _list = make_list( _list, split_item );
  }

  return _list;
}

# @brief Performs a file search WMI query against the target host using powershell provided functionalities, and also retrieves the file version.
#
# @param dir_path       The path to limit the query to (optional), Example: "\\Windows\\" (Without the drive letter and with the doubled trailing backslashes)
# @param dir_path_like  The path to limit the query to (optional) which is used in a LIKE statement, Example: "%windowssearchengine%"
# @param file_name      The file name to search for (mandatory, without the file extension), Example: "Safari"
# @param file_extension The file extension to limit the query to (optional), Example: "exe" (without a dot)
#
# @return An array of files and versions returned by the query, FALSE if no files exists matching the query or NULL
#         if not all required information are passed or the target system has denied the access
#
function powershell_wmi_file_search_version_query( dir_path, dir_path_like, file_name, file_extension ) {

  local_var dir_path, dir_path_like, file_name, file_extension;
  local_var kb_proxy_key, kb_proxy_list, _array, _split_item, _item, query, query_res, split_list, split_item;

  if( wmi_is_file_search_disabled() )
    return NULL;

  if( ! file_name ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_name#-#powershell_wmi_file_search_version_query" );
    return NULL;
  }

  if( dir_path && dir_path_like ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#dir_path and dir_path_like passed but only one of both can be used#-#powershell_wmi_file_search_version_query" );
    return NULL;
  }

  if( ! file_extension )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#file_extension#-#powershell_wmi_file_search_version_query" );

  if( ! dir_path )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dir_path#-#powershell_wmi_file_search_version_query" );

  kb_proxy_key = powershell_wmi_file_search_cache_key( dir_path:dir_path, dir_path_like:dir_path_like, file_name:file_name, file_extension:file_extension, function_name:"powershell_wmi_file_search_version_query" );

  kb_proxy_list = get_kb_list( kb_proxy_key );

  if( ! isnull( kb_proxy_list ) || kb_proxy_list ) {
    # nb: The function returns an array where we're saving the KB into in a form of "item#---#value"
    # because we can't save such an array into the KB.
    _array = make_array();
    foreach _split_item( kb_proxy_list ) {
      _item = split( _split_item, sep:"#---#", keep:FALSE );
      _array[_item[0]] = _item[1];
    }
    return _array;
  }

  query = powershell_wmi_file_search_construct_filter( dir_path:dir_path, dir_path_like:dir_path_like, file_name:file_name, file_extension:file_extension );

  query_res = powershell_wmi_query( classname:"CIM_DataFile", class_args:query, properties:"Name, Version", force_wmi_object:TRUE );

  if( ! query_res )
    return FALSE;

  _array = make_array();

  split_list = split( query_res, keep:FALSE );
  foreach split_item( split_list ) {
    # Note: ConvertTo-Cvs adds " around the fields, so we need to remove them
    split_item = str_replace( string:split_item, find:'"', replace:"" );
    _item = split( split_item, sep:";", keep:FALSE );
    set_kb_item( name:kb_proxy_key, value:_item[0] + "#---#" + _item[1] );
    _array[_item[0]] = _item[1];
  }

  return _array;
}

# @brief Checks if a given file exists
#
# @param filePath the path to the file to query (including the file extension), Example: "c:\\windows\\system32\\cmd.exe"
#
# @return TRUE if the path exists, FALSE otherwise or NULL if not all required information are passed.
#
function powershell_wmi_file_check_file_exists( filePath ) {

  local_var filePath, query, queryRes;

  if( ! filePath ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#filePath#-#powershell_wmi_file_check_file_exists" );
    return NULL;
  }

  query    = "-Filter \" + raw_string( 0x22 ) + "Name = '" + filePath + "'" + '\\"';
  queryRes = powershell_wmi_query( classname:"CIM_DataFile", class_args:query, properties:"Name" );

  if( ! queryRes )
    return FALSE;
  else
    return TRUE;
}

# @brief Gets information from windows services
#
# @param none, returns a list of services with properties
# @param svcName, returns details of a specific service
#
# @return info of a specific service or a list of services with properties

function powershell_wmi_svc_prop(svcName){

  local_var svcName;
  local_var cmd, svcList;

  if(!svcName){
    cmd = "get-wmiobject -query 'Select * from Win32_Service'";
  }
  else {
    cmd = "get-wmiobject -query 'Select * from Win32_Service Where Name = ''" + svcName + "'''";
  }

  svcList = powershell_cmd(cmd:cmd);

  if(("NTSTATUS" >< svcList) || !svcList){
    return(0);
  }

  return wmi_misc_split_res(List:svcList);
}

# @brief Performs a file search using Get-ChildItem on all drives.
#
# @param file_name_pattern The pattern of file to search for. Use * as wildcard if you want a pattern instead of exact file name
# @param dir_path          The directory path where to search (optional)
# @param dir_path_exclude  The directory path to exclude (optional)
#
# @return A list of files matching the query, on NULL if nothing was found
#
function powershell_file_search( file_name_pattern, dir_path, dir_path_exclude ) {

  local_var file_name_pattern, dir_path, dir_path_like;
  local_var cmd, all_files;

  cmd = "Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {'{0}\" + file_name_pattern + "' -f $_.DriveLetter} | ForEach-Object {& cmd.exe /c dir $_ /s /b} | ForEach-Object {Get-ItemProperty $_}";
  if( dir_path )
    cmd += " | Where-Object { $_.FullName -match '\\" + dir_path + "\\' }";
  if( dir_path_exclude )
    cmd += " | Where-Object { $_.FullName -notmatch '\\" + dir_path_exclude + "\\' }";
  cmd += " | ForEach-Object { $_.FullName };";

  if( ! all_files = powershell_cmd( cmd:cmd ) )
    return;

  return all_files;
}


# @brief Performs a file search and retrieves the specified version on all relevant drives
#
# @param file_name_pattern   The pattern of file to search for. Use * as wildcard if you want a pattern instead of exact file name
# @param dir_path            The directory path where to search (optional)
# @param dir_path_exclude    The directory path to exclude (optional)
# @param use_product_version True if ProductVersion should be used
#
# @return A list of files matching the query, on NULL if nothing was found
#
function powershell_file_search_version( file_name_pattern, dir_path, dir_path_exclude, use_product_version ) {

  local_var file_name_pattern, dir_path, dir_path_like;
  local_var cmd, all_files, version_field;

  cmd = "Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {'{0}\" + file_name_pattern + "' -f $_.DriveLetter} | ForEach-Object {& cmd.exe /c dir $_ /s /b} | ForEach-Object {Get-ItemProperty $_}";
  if( dir_path )
    cmd += " | Where-Object { $_.FullName -match '\\" + dir_path + "\\' }";
  if( dir_path_exclude )
    cmd += " | Where-Object { $_.FullName -notmatch '\\" + dir_path_exclude + "\\' }";
  version_field = "FileVersion";
  if( use_product_version )
    version_field = "ProductVersion";
  cmd += " | ForEach-Object { $_.FullName + ';'+ $_.VersionInfo." + version_field + " + ';' };";

  if( ! all_files = powershell_cmd( cmd:cmd ) )
    return;

  return all_files;
}