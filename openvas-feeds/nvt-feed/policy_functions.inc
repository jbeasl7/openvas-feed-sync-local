# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Global keys to avoid that we're repeatedly asking redis for something we already know
global_var __kb_smb_ver, __kb_host_cpe;

# @brief This function is used by basic policy tests. The silence value is set in
# compliance_tests.nasl. If you start the test within a standard policy like
# IT-Grundschutz, the results are silent by default. If you start the basic
# policy test by themselves, they are verbose.
#
# @param text the text to log
#
# @return NULL
#
function policy_logging(text, error) {

  local_var text, error;
  local_var verbose;

  verbose = get_kb_item("Compliance/verbose");
  if(verbose){
    if(error){
      log_message(data:text, port:0, proto:"Policy/Control/Error");
    }else{
      log_message(data:text, port:0, proto:"Policy/Control");
    }
  }
}

# @brief set kb entry for policy control oid
#
# @param oid of the policy control
#
# @return NULL
#
function policy_add_oid() {
  set_kb_item(name:"PolicyOIDs", value:get_script_oid());
}

# @brief set kb entry for policy control compliance status
#
# @param compliant if result is compliant with the policy control default value
#
# @return NULL
#
function policy_set_compliance(compliant) {

  local_var compliant;
  set_kb_item(name:get_script_oid() + "/COMPLIANT", value:string(compliant));
}

# @brief set kb entry for policy control result
#
# @param result of the policy control
#
# @return NULL
#
function policy_set_kb(val) {

  local_var val;

  # nb: save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:get_script_oid() + "/RESULT", value:chomp(string(val)));
}

# @brief set kb entry for policy control result if one result per user (like hku reg queries)
#
# @param id of the user
# @param val result for the user
#
# @return NULL
#
function policy_set_kb_hcu(id, val) {

  local_var id, val;

  # nb: save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:get_script_oid() + "/RESULT/" + id, value:chomp(string(val)));
}

# @brief set kb entry for policy control default value (compliance value)
#
# @param default of the policy control
#
# @return NULL
#
function policy_set_dval(dval) {

  local_var dval;

  # nb: save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:get_script_oid() + "/DEFAULT", value:chomp(string(dval)));
}

# @brief set kb entry for policy control fixtext
#
# @param fixtext of the policy control
#
# @return NULL
#
function policy_fixtext(fixtext) {

  local_var fixtext;

  set_kb_item(name:get_script_oid() + "/FIX", value:fixtext);
}

# @brief set kb entry for policy control title
#
# @param title of the policy control
#
# @return NULL
#
function policy_control_name(title) {

  local_var title;

  title = str_replace(string:title, find:'\n', replace:' ');
  set_kb_item(name:get_script_oid() + "/NAME", value:title);
}

# @brief set kb entry for policy control test type and command
#
# @param type what type of test used in Policy Control (RegKey, SSH_Cmd etc.)
#        cmd what command was used to get the result
#
# @return NULL
#
function policy_testtype(type, cmd) {

  local_var type, cmd;

  if(!cmd)
    cmd = "None";

  if(!type)
    type = "None";

  set_kb_item(name:get_script_oid() + "/TEST_TYPE", value:type);
  set_kb_item(name:get_script_oid() + "/CMD", value:cmd);
}

# @brief deprecated function for logging regkey entries
#
# @param type of regkey (HKU / HKLM / HKCU)
# @param key of regkey
# @param item of regkey
# @param value result found on host
#
# @return NULL
#
function policy_logging_registry(type, key, item, value) {

  local_var type, key, item, value;

  policy_logging(text:'Registry value ' + type + '\\' + key + '!' + item + ' is set to: ' + value);
}

# @brief Log message in policy control format
#
# @param result what result found on host
# @param default what need to be set to be compliant
# @param compliant compliance status (yes, no, error)
# @param fixtext how to fix non-compliance
# @param type of test (RegKey, SSH_Cmd etc.)
# @param test command to run / regkey etc.
# @param info additional information like comments
#
# @return NULL
#
function policy_reporting(result, default, compliant, fixtext, type, test, info) {

  local_var result, default, compliant, fixtext, type, test, info;
  local_var report;

  # Be aware that a backslash in a result value causes the string() function to throw an error
  if(!string(result)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_reporting#-#result");
    result = "Unknown";
  }

  # Be aware that a backslash in a default value causes the string() function to throw an error
  if(!string(default)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_reporting#-#default");
    default = "Unknown";
  }

  if(!compliant) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_reporting#-#compliant");
    compliant = "Incomplete";
  }

  if(!fixtext) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_reporting#-#fixtext");
    fixtext = "Unknown";
  }

  if(!type) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_reporting#-#type");
    type = "Unknown";
  }

  if(!test) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_reporting#-#test");
    test = "Unknown";
  }

  if(info){
    set_kb_item(name:get_script_oid() + "/NOTE", value:info);
    report = policy_build_report(result:result, default:default, compliant:compliant, fixtext:fixtext,
      type:type, test:test, info:info);
  }else{
    report = policy_build_report(result:result, default:default, compliant:compliant, fixtext:fixtext,
      type:type, test:test);
  }

  policy_logging(text:report);
}

# @brief Runs a passed WMI db query against 'root\rsop\computer' and compare the result to a default value
#
# @param query Query for WMI db
# @param default value to compare compliance to
# @param min if default should be the minimum
# @param max if default should be the maximum
#
# @note rsop only delivers results for domain admins
#
# @return ret array with value, comment and compliant strings
#
function policy_rsop_query(query, default, min, max) {

  local_var query, default, min, max;
  local_var infos, ret, handle, res, splitRes;

  if(query =~ "SecuritySettingBoolean") {
    if(min)
      set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_rsop_query: 'query' contains SecuritySettingBoolean and 'min' is set to TRUE which is not compatible.");
    if(max)
      set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_rsop_query: 'query' contains SecuritySettingBoolean and 'max' is set to TRUE which is not compatible.");
  }

  if(!query)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_rsop_query#-#query");

  if(isnull(default))
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_rsop_query#-#default");

  infos = kb_smb_wmi_connectinfo();
  if(!infos){
    ret["value"] = "Error";
    ret["compliant"] = "incomplete";
    ret["comment"] = "No authentication possible.";

    return(ret);
  }

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"], ns:'root\\rsop\\computer');
  if(!handle) {
    ret["value"] = "Error";
    ret["compliant"] = "incomplete";
    ret["comment"] = "No WMI connection possible.";

    return(ret);
  }

  res = wmi_query_rsop(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);
  if(!res){
    if(tolower(default) == "none")
      ret["compliant"] = "yes";
    else
      ret["compliant"] = "no";

    ret["value"] = "None";
    ret["comment"] = "No setting found for this query.";

    return(ret);
  }

  splitRes = split(res, sep:"|", keep:FALSE);

  # Setting is on 4th position
  if(max_index(splitRes) < 4)
    ret["value"] = "None";
  else
    ret["value"] = chomp(splitRes[4]);

  if(default == ret["value"])
    ret["compliant"] = "yes";
  else if(min && int(ret["value"]) >= int(default))
    ret["compliant"] = "yes";
  else if(max && int(ret["value"]) <= int(default))
    ret["compliant"] = "yes";
  else
    ret["compliant"] = "no";

  return(ret);
}

# @brief query wmi db RSOP_UserPrivilegeRight for specific right
#
# @param select what to show from db
# @param keyname which user right to search for
#
# @note rsop only delivers results for domain admins
#
# @return accounts as string
#
function rsop_userprivilegeright(select, keyname) {

  local_var select, keyname;
  local_var infos, handle, query, res, splitRes, accountList, MaxIndexAccountList, i, returnValue;

  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    return;

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"], ns:'root\\rsop\\computer');
  if(!handle)
    return;

  query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = '" + keyname + "'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);
  res = chomp(res);
  if(!res)
    return "None";

  splitRes = split(res, keep:FALSE);
  accountList = split(splitRes[1], sep:"|", keep:FALSE);
  MaxIndexAccountList = max_index(accountList);
  for(i = 0; i < MaxIndexAccountList - 2; i++) {
    returnValue += ", " + accountList[i];
  }

  returnValue = str_replace(string:returnValue, find:", ", replace:"", count:1);
  return(returnValue);
}

# @brief query wmi db RSOP_UserPrivilegeRight for specific right and compare to default
#
# @param select what to show from db
# @param keyname which user right to search for
# @param default set point to be compliant
#
# @note rsop only delivers results for domain admins
#
# @return ret array with value, comment and compliant strings
#
function policy_rsop_match(select, keyname, default){
  local_var select, keyname, default, ret, user_list, _user, default_list, user_list_split;

  if(!(user_list = rsop_userprivilegeright(select:select, keyname:keyname))){
    ret["compliant"] = "incomplete";
    ret["value"] = "None";
    ret["comment"] = "No WMI query possible";
    return(ret);
  }

  if(user_list == "None" && default == "None"){
    ret["compliant"] = "yes";
    ret["value"] = "None";
    ret["comment"] = "No account found for this setting";
    return(ret);
  }else if(user_list == "None"){
    ret["compliant"] = "no";
    ret["value"] = "None";
    ret["comment"] = "No account found for this setting";
    return(ret);
  }

  ret["compliant"] = "yes";
  ret["comment"] = "";
  ret["value"] = user_list;

  user_list_split = split(user_list, sep:',', keep:FALSE);
  foreach _user (user_list_split){
    _user = ereg_replace(string:chomp(_user), pattern:"^\s+", replace:"");
    if(_user >< default)
      continue;

    ret["compliant"] = "no";
  }

  default_list = split(default, sep:",", keep:FALSE);
  foreach _user (default_list){
    _user = ereg_replace(string:chomp(_user), pattern:"^\s+", replace:"");
    if(_user >< user_list)
      continue;

    ret["compliant"] = "no";
  }

  return(ret);
}

# @brief gets the status of a user account on windows hosts
#
# @param select what to return from WMI query
# @param name of the user account
#
# @return the selection from the wmi db
#
function win32_useraccount(select, name) {

  local_var select, name;
  local_var infos, handle, query, res;

  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    exit(0);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
  if(!handle) {
    policy_logging(text:"WMI Connect to host failed.");
    policy_set_kb(val:"error");
    exit(0);
  }

  query = "SELECT " + select + " FROM Win32_UserAccount WHERE Name = '" + name + "'";
  res = wmi_query(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);

  return(res);
}

# @brief Checks for a package whether it is installed and if so, which version
#
# @param package The package to check the existence / version
# @param maintainer The package maintainer (RPM or DEB)
#
# @note Add a dependency to "gather-package-list.nasl" if you want to use this function
#
# @return A string with the version or NULL if not installed on host
#
function get_package_version(package, partial_match) {

  local_var package, partial_match;
  local_var packages_string, packages_list, _pak, packages_split, name, version, _line, line_split, packages_info;

  if(!package) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#package_version#-#package");
    return;
  }

  if(packages_string = get_kb_item("ssh/login/rpms")) {
    packages_list = split(packages_string, sep:";", keep:FALSE);
    foreach _pak(packages_list) {
      package_split = split(_pak, sep:"~", keep:FALSE);
      name = package_split[0];
      version = package_split[1];
      if(partial_match) {
        if(package >< name) {
          return version;
        }
      }else{
        if(name == package) {
          return version;
        }
      }
    }
  } else if(packages_string = get_kb_item("ssh/login/packages")) {
    packages_list = split(packages_string, keep:FALSE);
    foreach _line(packages_list) {
      if(_line =~ "^ii") {
        line_split = ereg_replace(string:_line, pattern:"\s+", replace:"|");
        packages_info = split(line_split, sep:"|", keep:FALSE);
        name = packages_info[1];
        version = packages_info[2];
        if(partial_match) {
          if(package >< name) {
            return version;
          }
        }else{
          if(name == package) {
            return version;
          }
        }
      }
    }
  }
  return;
}

# @brief Tries to find a GRUB bootloader config file on the host.
#        Searches for grub.conf, grub.cfg or menu.lst in directories
#        /boot/grub/ or /boot/grub2/.
#
# @return Filepath if config file found or NULL if not found
#         (maybe because of denied read permissions)
#
function get_grub_config_file() {

  local_var grub_config_files, grub_config_dirs, _dir, _file, config_file;

  grub_config_files = make_list('grub.conf', 'grub.cfg', 'menu.lst');
  grub_config_dirs = make_list('/boot/grub/', '/boot/grub2/');

  foreach _dir(grub_config_dirs) {
    foreach _file(grub_config_files) {
      config_file = ssh_find_file(file_name:_dir + _file);
      if(config_file)
        return config_file[0];
    }
  }
  return;
}

# @brief sends a ssh_cmd and filters errors in return values.
#
# @deprecated Please use @ref ssh_cmd from ssh_func.inc and add possible
#             pattern to filter out directly into that function.
#
# @param socket the socket for the ssh command
# @param cmd the bash command
#
# @return return of the command or NULL if file not found or
#         other error occurred
#
function ssh_cmd_without_errors(socket, cmd) {

  local_var socket, cmd;
  local_var ret;

  ret = ssh_cmd(socket:socket, cmd:cmd, return_errors:FALSE);

  if('No such file or directory' >< ret ||
    'command not found' >< ret ||
    'esxcli: error' >< ret)
    return;

  return(ret);
}

# @brief checks the file permissions, gid and uid with stat command
#        on a linux host
#
# @param file the file to check
# @param sock socket for the ssh command
#
# @return an array with keys permissions, gid and uid or NULL if none found.
#
function linux_file_permissions(file, socket) {

  local_var file, socket;
  local_var stat_cmd, stat, return_array;

  if(!socket) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#socket");
    return;
  }

  if(!file) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#file");
    return;
  }

  stat_cmd = "stat " + file;
  stat = ssh_cmd_without_errors(socket:socket, cmd:stat_cmd);
  if(stat && ("permission denied" >!< tolower(stat))) {
    return_array = make_array();
    return_array["gid"] = policy_chown_get_gid(stat:stat);
    return_array["uid"] = policy_chown_get_uid(stat:stat);
    return_array["permissions"] = policy_get_access_permissions(stat:stat);

    return(return_array);
  }
  return;
}

# @brief check if a service is enabled on a Linux host.
#        Uses systemctl is-enabled, chkconfig --list and
#        at last search for service in /etc/rc*.d files
#
# @param service the service to search for
# @param socket socket for the ssh command
#
# @return TRUE if service is enabled, NULL if not
#
function linux_service_is_enabled(service, socket) {

  local_var service, socket;
  local_var systemctl_cmd, systemctl, chkconfig_cmd, chkconfig, ls_grep_cmd, ls_grep, enabled;

  if(!socket) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#socket");
    return;
  }

  if(!service) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#service");
    return;
  }

  systemctl_cmd = 'systemctl is-enabled ' + service;
  systemctl = ssh_cmd_without_errors(socket:socket, cmd:systemctl_cmd);
  if('enabled' >< systemctl) {
    return TRUE;
  }

  chkconfig_cmd = 'chkconfig --list ' + service;
  chkconfig = ssh_cmd_without_errors(socket:socket, cmd:chkconfig_cmd);
  if('2:on' >< chkconfig && '3:on' >< chkconfig && '4:on' >< chkconfig && '5:on' >< chkconfig) {
    return TRUE;
  }

  ls_grep_cmd = 'ls /etc/rc*.d | grep ' + service;
  ls_grep = ssh_cmd_without_errors(socket:socket, cmd:ls_grep_cmd);
  enabled = eregmatch(string:ls_grep, pattern:'[\\^S][^\n\r]*');
  if(enabled)
    return TRUE;

  return;
}

# @brief check if a service is enabled on a Linux host.
#        Uses systemctl is-enabled, chkconfig --list and
#        at last search for service in /etc/rc*.d files
#
# @param service the service to search for
# @param socket socket for the ssh command
#
# @return TRUE if service is enabled, NULL if not
#
function check_permission_denied(value, file) {

  local_var value, file;
  local_var ret;

  if('permission denied' >< tolower(value)) {
    ret = 'No permission to read in file "' + file + '".';
    return(ret);
  }
  return;
}

# @brief Tests if key SMB/WindowsVersion is at least a given Windows Version.
#
# @param min_ver minimal Windows version (as string)
#
# @return TRUE if SMB/WindowsVersion is set and meets at least the given version, FALSE if not
#
function policy_verify_win_ver(min_ver){
  local_var min_ver, cur_ver;

  if(min_ver && min_ver !~ "^[0-9.]+$") {
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_verify_win_ver: wrong syntax in 'min_ver', passed: " + min_ver + ", expected e.g. 6{.2}");
    return NULL; # To differ between "FALSE" (its not a windows) and "NULL" (we don't know because syntax is wrong)
  }

  cur_ver = get_kb_item("SMB/WindowsVersion");

  if(!cur_ver)
    return FALSE;

  if(cur_ver && cur_ver !~ "^[0-9.]+$") {
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_verify_win_ver: wrong syntax in 'cur_ver', extracted: " + cur_ver + ", expected e.g. 6{.2}");
    return NULL; # To differ between "FALSE" (its not a windows) and "NULL" (we don't know because syntax is wrong)
  }

  if(!min_ver && cur_ver)
    return TRUE;

  if(version_is_greater_equal(version:cur_ver, test_version:min_ver))
    return TRUE;

  return FALSE;
}

# @brief Returns reporting variables for wrong os
#
# @param target_os OS of host that should be matched (at least)
#
# @return ret array with value, comment and compliant strings
#
function policy_report_wrong_os(target_os){
  local_var target_os, ret;

  ret["value"] = "None";
  ret["comment"] = "Host does not run " + target_os + ".";
  ret["compliant"] = "incomplete";

  return ret;
}

# @brief Returns results variables for exact reg_dword check
#
# @param key Registry key to check
# @param item Registry item to check
# @param type Registry type to check
# @param default set point to check the actual value against
#
# @return ret array with value, comment and compliant strings
#
function policy_match_exact_reg_dword(key, item, type, default){
  local_var key, item, type, default;
  local_var value, comment, compliant, ret;

  value = registry_get_dword(key:key, item:item, type:type);
  value = chomp(value);

  if(value == ""){
    comment = "Registry key not found.";
    compliant = "incomplete";
    value = "None";
  }else{
    if(isnull(default) || default == ""){
      compliant = "incomplete";
    }else if(int(value) == int(default)){
      compliant = "yes";
    }else{
      compliant = "no";
    }
  }

  ret["value"] = value;
  ret["compliant"] = compliant;
  if(comment){
    ret["comment"] = comment;
  }else{
    ret["comment"] = "";
  }

  return ret;
}

# @brief Returns results variables for exact or partial reg_sz check
#
# @param key Registry key to check
# @param item Registry item to check
# @param type Registry type to check
# @param default set point to check the actual value against
#
# @return ret array with value, comment and compliant strings
#
function policy_match_reg_sz(key, item, type, default, partial, multi_sz){
  local_var key, item, type, default, partial, multi_sz;
  local_var value, comment, compliant, ret, lower_value, lower_default;

  if(multi_sz){
    value = registry_get_sz(key:key, item:item, type:type, multi_sz:TRUE);
    if(value)
      value = str_replace(string:value, find:'\n', replace:",");
  }else{
    value = registry_get_sz(key:key, item:item, type:type);
  }

  value = chomp(value);
  if(!value || isnull(value)){
    value = "Unknown";
    compliant = "incomplete";
  }else{
    lower_value = tolower(string(value));
    lower_default = tolower(string(default));

    if(partial && lower_default >< lower_value){
      compliant = "yes";
    }else if(lower_value == lower_default){
      compliant = "yes";
    }else{
      compliant = "no";
    }
  }

  ret["value"] = value;
  ret["compliant"] = compliant;
  if(comment){
    ret["comment"] = comment;
  }else{
    ret["comment"] = "";
  }

  return ret;
}

# @brief Sets the result keys to the KB
#
# @param type The type of the test
# @param cmd The actual command of the test
# @param default set point for the policy control
# @param solution how to fix non-compliance
# @param title title of the policy control
# @param value the actual value found on the host
# @param compliant compliance status of the policy control
#
function policy_set_kbs(type, cmd, default, solution, title, value, compliant){
  local_var type, cmd, default, solution, title, value, compliant;

  if(!type)
    type = "Unknown";

  if(!cmd)
    cmd = "Unknown";

  if(!default)
    default = "Unknown";

  if(!solution)
    solution = "Unknown";

  if(!title)
    title = "Unknown";

  if(!value)
    value = "Unknown";

  if(!compliant)
    compliant = "incomplete";

  policy_testtype(type:type, cmd:cmd);
  policy_add_oid();
  policy_set_dval(dval:default);
  policy_fixtext(fixtext:solution);
  policy_control_name(title:title);
  policy_set_kb(val:value);
  policy_set_compliance(compliant:compliant);
}

# @brief Checks if SSH login is possible and if host runs Linux OS
#
# @return boolean TRUE if Linux shell and SSH login was possible, FALSE if not
#
function policy_check_linux_ssh_shell(){
  if(!get_kb_item("login/SSH/success") || get_kb_item("ssh/no_linux_shell") ||
      get_kb_item("ssh/restricted_shell")){
    return(FALSE);
  }
  return(TRUE);
}

# @brief Returns reporting variables when user list is empty
#
# @return ret array with value, comment and compliant strings
#
function policy_report_empty_hku(){
  local_var ret;

  ret["value"] = "None";
  ret["comment"] = "No valid SIDs found in HKU.";
  ret["compliant"] = "incomplete";

  return ret;
}

# @brief Returns reporting variables for registry dword for multiple SIDs
#
# @param key The registry key to look in
# @param item The registry item to look for
# @param default The set point to be compliant
# @param sids List of SIDs in HKU to look for
#
# @return ret array with value, comment and compliant strings
#
function policy_match_exact_dword_profiles(key, item, default, sids){
  local_var key, item, default, sids;
  local_var incomplete_sids, fail_sids, ret, _sid, value;

  incomplete_sids = "";
  fail_sids = "";
  ret["compliant"] = "yes";
  ret["value"] = default;
  ret["comment"] = "";

  foreach _sid (sids){
    # filter non-standard-accounts
    if(_sid !~ "^S-1-5-[0-9,-]+$" || _sid =~ "^S-1-5-(18|19|20)") continue;
    key = strcat(_sid, "\", key);
    value = registry_get_dword(key:key, item:item, type:"HKU");
    value = chomp(value);
    if(!value){
      incomplete_sids += ", " + _sid;
    }else if(int(value) != int(default)){
      fail_sids += ", " + _sid;
    }
  }

  if(incomplete_sids != ""){
    ret["compliant"] = "incomplete";
    ret["value"] = "None";
    ret["comment"] = "Registry key not found for SIDs: " + str_replace(string:incomplete_sids,
      find:", ", replace:"", count:1);
  }

  if(fail_sids != ""){
    ret["compliant"] = "no";
    ret["value"] = "None";
    if(ret["comment"] != ""){
      # Let reporting begin in same indentation as before
      ret["comment"] += '\n              ';
    }
    ret["comment"] += "Non compliant SIDs: " + str_replace(string:fail_sids, find:", ", replace:"",
      count:1);
  }

  return(ret);
}

# @brief Returns reporting variables for registry dword for multiple SIDs
#
# @param users Number of users
# @param setting Setting under the user SID
# @param pspath KB ID for SID
# @param default Passing value
# @nullconfigpass Not explicitly configured in the registry and default passes for recommendation
#
# @return ret array with value, comment and compliant strings
#
function policy_compare_office_config(users, setting, pspath, default, notconfigpass){
  local_var users, setting, pspath, default, notconfigpass;
  local_var ret, u, val, currValue;

  compliant = "incomplete";
  ret["value"] = default;

  # Each user SID configuration
  for(u = 1; u <= users; u++){
    currValue = get_kb_item("policy/microsoft/office/" + u + setting);

    if(currValue == default){
    }else if(!currValue && notconfigpass == TRUE){
      val += "Not configured (default)" + '\n';
    }else{
      compliant = "no";
      comment += get_kb_item("policy/microsoft/office/" + u + pspath) + '\n' + "Value: " + currValue + '\n';
      val = currValue;
    }
  }

  if("no" >!< compliant){
    ret["compliant"] = "yes";
  }else{
    ret["compliant"] = "no";
  }
  ret["comment"] = comment;
  if(val){
    ret["value"] = val;
  }
  return(ret);
}

# @brief Sets kbs for Office product configurations
# @param configs are results from a powershell command
# @param product is the unique name for the group of configurations collected
function policy_office_set_kb(configs, product){
  local_var configs, product, setting, keyname;

  user_count = 1;
  foreach config(split(configs, keep:FALSE)){
    if(!config || config =~ "^\s" || config =~ "^\s*$" || config =~ "PSProvider" || config =~ "PSParentPath" || config =~ "PSChildName"){
    }else{
      values = eregmatch(string:config, pattern:"^(.+)\s*:\s*(.+)$");
      keyname = values[1];
      setting = values[2];
      setting = ereg_replace(string:setting, pattern:"\s+", replace:"");
      kb = "policy/microsoft/office/" + user_count + "/" + product + "/" + tolower(keyname);
      kb = ereg_replace(string:kb, pattern:"\s+", replace:"");
      set_kb_item(name:kb, value:setting);
      if(config =~ "PSPath"){user_count++;}
    }
  }
  user_count -= 1;
  set_kb_item(name:"policy/microsoft/office/" + product + "/users", value:user_count);
}


# @brief Returns reporting variables for registry dword for multiple SIDs
#
# @param users Number of users
# @param setting Setting under the user SID
# @param pspath KB ID for SID
# @param default Passing value
# @nullconfigpass Not explicitly configured in the registry and default passes for recommendation
#
# @return ret array with value, comment and compliant strings
#
function policy_compare_chrome_config(users, setting, pspath, default, notconfigpass){
  local_var users, setting, pspath, default, notconfigpass;
  local_var ret, u, val, currValue;

  compliant = "incomplete";
  ret["value"] = default;

  # Each user SID configuration
  for(u = 1; u <= users; u++){
    currValue = get_kb_item("policy/google" + setting);
    if(currValue == default){
    }else if(!currValue && notconfigpass == TRUE){
      val += "Not configured (default)" + '\n';
    }else{
      compliant = "no";
      if(currValue){
        comment += get_kb_item("policy/google" + pspath) + '\n' + "Value: " + currValue + '\n';
        val = currValue;
      }else{
        val = "None";
        comment += "Not configured";
      }
    }
  }

  if("no" >!< compliant){
    ret["compliant"] = "yes";
  }else{
    ret["compliant"] = "no";
  }
  ret["comment"] = comment;
  if(val){
    ret["value"] = val;
  }
  return(ret);
}


# @brief Sets kbs for Chrome product configurations
# @param configs are results from a powershell command
# @param product is the unique name for the group of configurations collected
function policy_chrome_set_kb(configs, product){
  local_var configs, product, setting, keyname;


  foreach config(split(configs, keep:FALSE)){
    if(!config || config =~ "^\s" || config =~ "^\s*$" || config =~ "PSProvider" || config =~ "PSParentPath" || config =~ "PSChildName"){
    }else{
      values = eregmatch(string:config, pattern:"^(.+)\s*:\s*(.+)$");
      keyname = values[1];
      setting = values[2];
      setting = ereg_replace(string:setting, pattern:"\s+", replace:"");
      kb = "policy/google/" + product + "/" + keyname;
      kb = ereg_replace(string:kb, pattern:"\s+", replace:"");
      set_kb_item(name:kb, value:setting);
      if(config =~ "PSPath"){user_count++;}
    }
  }
  user_count = 1;
  set_kb_item(name:"policy/google/" + product, value:user_count);
}


# @brief Checks if the host runs Windows 10.
#
# @return bool TRUE if host runs Microsoft Windows 10, FALSE if not
#
function policy_host_runs_windows_10(){
  local_var win_ver, host_cpe;
  # nb: __kb_smb_ver and __kb_host_cpe are global vars

  if(!isnull(__kb_smb_ver)){
    win_ver = string(__kb_smb_ver);
  }else{
    win_ver = string(get_kb_item("SMB/WindowsVersion"));
    if(strlen(win_ver) > 0) {
      __kb_smb_ver = win_ver;
    }else{
      return(FALSE);
    }
  }

  if(!isnull(__kb_host_cpe)){
    host_cpe = string(__kb_host_cpe);
  }else{
    host_cpe = os_get_best_cpe();
    if(strlen(host_cpe) > 0) {
      __kb_host_cpe = host_cpe;
    }else{
      return(FALSE);
    }
  }

  if(win_ver && (host_cpe =~ "microsoft:windows_10"))
    return(TRUE);

  return(FALSE);
}

# @brief Checks if wmi access to the host was possible
#
# @return TRUE if WMI access is possible, FALSE if not
#
function policy_wmi_access(){

  if(!get_kb_item("WMI/access_successful"))
    return(FALSE);

  return(TRUE);
}

# @brief Returns reporting variables for no WMI access
#
# @return ret array with value, comment and compliant strings
#
function policy_report_no_wmi_access(){
  local_var ret;

  ret["value"] = "None";
  ret["comment"] = "No WMI access to the host possible.";
  ret["compliant"] = "incomplete";

  return(ret);
}

# @brief Returns results variables for exact reg_dword check
#
# @param key Registry key to check
# @param item Registry item to check
# @param type Registry type to check
# @param default set point to check the actual value against
# @param min default is the minimum value, actual value can not be higher
# @param max default is the maximum value, actula value can not be higher
# @param not_zero if a maximum is given, the actual value can not be 0
# @param as_sz if the value is saved as sz, this can be tested
#
# @return ret array with value, comment and compliant strings
#
function policy_min_max_reg_dword(key, item, type, default, min, max, not_zero, as_sz){
  local_var key, item, type, default, min, max, not_zero, as_sz;
  local_var value, comment, compliant, ret;

  if(!min && !max){
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_min_max_reg_dword#-#min_max");
  }

  if(as_sz)
    value = registry_get_sz(key:key, item:item, type:type);
  else
    value = registry_get_dword(key:key, item:item, type:type);

  value = chomp(value);

  if(value == ""){
    comment = "Registry key not found.";
  }else{
    if(min){
      if(int(value) >= int(default))
        compliant = "yes";
      else
        compliant = "no";
    }

    if(max){
      if(int(value) <= int(default)){
        if(not_zero && int(value) == 0)
          compliant = "no";
        else
          compliant = "yes";
      }else{
        compliant = "no";
      }
    }
  }

  if(!value)
    ret["value"] = "None";
  else
    ret["value"] = value;

  if(!compliant)
    ret["compliant"] = "incomplete";
  else
    ret["compliant"] = compliant;

  if(!comment)
    ret["comment"] = "";
  else
    ret["comment"] = comment;

  return ret;
}

# @brief Performs a WMI query against a host and returns finding
#
# @param query The WMI query to use.
#
# @return A string containing the result of the WMI query or FALSE if
#         no connection to the remote host was possible or if the query failed.
#
function policy_wmi_query(query){
  local_var query, infos, handle, res;

  if(!string(query)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_wmi_query#-#query");
    return(FALSE);
  }

  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    return(FALSE);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
  if(!handle)
    return(FALSE);

  res = wmi_query(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);

  if(!res || "NTSTATUS" >< res)
    return(FALSE);

  return(res);
}

# @brief Returns reporting variables for no powershell return
#
# @return ret array with value, comment and compliant strings
#
function policy_report_no_powershell_result(){
  local_var ret;

  ret["value"] = "None";
  ret["comment"] = "The powershell command did not return any result. Reasons: Command does not exist, powershell.exe access was denied";
  ret["compliant"] = "incomplete";

  return(ret);
}

# @brief Returns reporting variables for powershell return
#
# @return ret array with value, comment and compliant strings
#
function policy_report_powershell_result(value){
  local_var ret, value;

  ret["value"] = value;
  ret["comment"] = "This script only shows the output of the powershell command.";
  ret["compliant"] = "yes";

  return(ret);
}

# @brief Returns reporting variables for advanced audit setting on Windows hosts
#
# @param key The name of the auditing variable
# @param default The default value it should have
#
# @return ret array with value, comment and compliant strings
#
function policy_win_get_advanced_audit_results(key, default){
  local_var ret, key, default, value;

  value = get_kb_item(key);

  if(!value){
    ret["value"] = "None";
    ret["compliant"] = "incomplete";
    ret["comment"] = "Can not determine audit status";
  }else{
    ret["value"] = value;
    if(default >< value)
      ret["compliant"] = "yes";
    else
      ret["compliant"] = "no";
  }

  return(ret);
}

# @brief Returns results variables for multiple reg keys at once
#
# @param key Registry key to check
# @param type Registry type to check
# @param item_default_array array of items and defaults to check
# @param reg_sz If registry value is REG_SZ
# @param reg_dword If registry value is REG_DWORD
#
# @return ret array with value, comment and compliant strings
#
function policy_match_multiple_reg_values(key, type, item_default_array, reg_sz, reg_dword){
  local_var key, type, item_default_array, reg_sz, reg_dword;
  local_var compliant, _item, default, value, comment, total_value, ret;

  if(!item_default_array || !key || !type){
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_match_multiple_reg_values#-#VALUES");
    return;
  }

  compliant = "yes";

  foreach _item (keys(item_default_array)){
    default = item_default_array[_item];

    if(reg_sz)
      value = registry_get_sz(key:key, item:_item, type:type);
    else
      value = registry_get_dword(key:key, item:_item, type:type);

    value = chomp(value);
    if(value == ""){
      comment += ", Registry key not found: " + _item;
      if(compliant != "no")
        compliant = "incomplete";
      total_value += ", " + _item + ": None";
    }else{
      if(value != default)
        compliant = "no";
      total_value += ", " + _item + ": " + value;
    }
  }

  ret["value"] = str_replace(string:total_value, find:", ", replace:"", count:1);
  ret["compliant"] = compliant;
  if(comment)
    ret["comment"] = str_replace(string:comment, find:", ", replace:"", count:1);
  else
    ret["comment"] = "";

  return ret;
}

# @brief Cut a string on a "count" occurrence of a pattern
#
# @param str the string to cut
# @param sep the separation string / char
# @param count the x occurrence of the pattern where to cut the string
# @param glue char which is used to concat the substrings again
#
# @return major_version the concatenated string
#
function policy_get_major_version_app(str, sep, count, glue){
  local_var str, sep, count, glue, split_version, counter, major_version;

  split_version = split(str, sep:sep, keep:FALSE);

  for(counter = 0; counter < count; counter++){
    if(counter == 0)
      major_version = string(split_version[counter]);
    else
      major_version = string(major_version, glue, split_version[counter]);
  }

  return(major_version);
}

# @brief Returns reporting variables for wrong or missing app
#
# @param target_app App of host that should be matched
#
# @return ret array with value, comment and compliant strings
#
function policy_report_wrong_app(target_app){
  local_var target_app, ret;

  ret["value"] = "None";
  ret["comment"] = "No installation found for software: " + target_app + ".";
  ret["compliant"] = "incomplete";

  return ret;
}

# @brief Build a list from a comma separated string
#
# @param str comma separated app list as a string
#
# @return ret list of apps
#
function policy_build_list_from_string(str){
  local_var str, app_list, counter;

  app_list = split(str, sep:",", keep:"FALSE");

  for(counter = 0; counter < max_index(app_list); counter ++){
    app_list[counter] = ereg_replace(string:chomp(app_list[counter]), pattern:"^(\s+)", replace:"");
  }

  return(app_list);
}

# @brief Build a item default list from a list
#
# @param list the list with items
# @param default the set points for the items
#
# @return ret list of items with set points
#
function policy_build_items_default_list(list, default){
  local_var list, default, _item, ret;

  foreach _item (list){
    ret[_item] = default;
  }

  return(ret);
}

# @brief Return string for Microsoft Windows OS
#
# @return Microsoft Windows string
#
function policy_microsoft_windows_target_string(){
  return("Microsoft Windows");
}

# @brief build report for Policy Controls
#
# @param result what result found on host
# @param default what need to be set to be compliant
# @param compliant compliance status (yes, no, error)
# @param fixtext how to fix non-compliance
# @param type of test (RegKey, SSH_Cmd etc.)
# @param test command to run / regkey etc.
# @param info additional information like comments
#
# @return report string in format as understood by Greenbone Compliance Report format
#
function policy_build_report(result, default, compliant, fixtext, type, test, info){

  local_var result, default, compliant, fixtext, type, test, info;
  local_var report;

  report += "Compliant:    " + toupper(compliant) + '\n';
  report += "Actual Value: " + result + '\n';
  report += "Set Point:    " + default + '\n';
  report += "Type of Test: " + type + '\n';
  report += "Test:         " + test + '\n';
  report += "Solution:     " + fixtext;

  if(info){
    report += '\n' + "Notes:        " + info;
  }

  return (report);
}

# @brief Check compliance for a given value and set_point
#
# @param value of setting on host
# @param set_point value to be compliant
#
# @return "yes" if compliant or "no" otherwise
#
function policy_setting_exact_match(value, set_point){
  local_var value, set_point;

  if(isnull(value) || isnull(set_point))
    return("incomplete");

  if(value == set_point)
    return("yes");
  else
    return("no");
}

# @brief Check compliance for a given value and set_point
#
# @param value of setting on host
# @param set_point minimum value to be compliant
#
# @return "yes" if compliant or "no" otherwise
#
function policy_setting_min_match(value, set_point){
  local_var value, set_point;

  if(!value || !set_point)
    return("incomplete");

  if(value == set_point){
    return("yes");
  }

  if(value !~ "[0-9]+" || set_point !~ "[0-9]+")
    return("no");

  value = ereg_replace(string:chomp(value), pattern:"^(\s+)", replace:"");
  set_point = ereg_replace(string:chomp(set_point), pattern:"^(\s+)", replace:"");

  if(int(value) >= int(set_point))
    return("yes");
  else
    return("no");
}

# @brief Check compliance for a given value and set_point
#
# @param value of setting on host
# @param set_point maximum value to be compliant
# @param non_zero set to TRUE, if value should not be zero
#
# @return "yes" if compliant or "no" otherwise
#
function policy_setting_max_match(value, set_point, non_zero){
  local_var value, set_point, non_zero;

  if(!value || !set_point)
    return("incomplete");

  if(value == set_point){
    return("yes");
  }else if(non_zero && value == "0"){
    return("no");
  }

  if(value !~ "[0-9]+" || set_point !~ "[0-9]+")
    return("no");

  value = ereg_replace(string:chomp(value), pattern:"^(\s+)", replace:"");
  set_point = ereg_replace(string:chomp(set_point), pattern:"^(\s+)", replace:"");

  if(int(value) <= int(set_point))
    return("yes");
  else
    return("no");
}

# @brief Check compliance for a given value and set_point
#
# @param value of setting on host
# @param min minimum value to be compliant
# @param max maximum value to be compliant
#
# @return "yes" if compliant or "no" otherwise
#
function policy_setting_in_range(value, min, max){
  local_var value, min, max;

  if(!value || !min || !max)
    return("incomplete");

  if(value !~ "[0-9]+" || min !~ "[0-9]+" || max !~ "[0-9]+")
    return("no");

  value = ereg_replace(string:chomp(value), pattern:"^(\s+)", replace:"");
  min = ereg_replace(string:chomp(min), pattern:"^(\s+)", replace:"");
  max = ereg_replace(string:chomp(max), pattern:"^(\s+)", replace:"");

  if(int(value) >= int(min) && int(value) <= int(max))
    return("yes");
  else
    return("no");
}

# @brief Check if all items from list exist in another list
#
# @param value string which needs to contain set_points
# @param set_points  list of set points
# @param sep separator in set_points list
#
# @return "yes" if compliant or "no" otherwise
#
function policy_settings_list_in_value(value, set_points, sep){
  local_var value, set_points, sep, compliant, default_list, _setting;

  if(!value || !set_points)
    return("incomplete");

  compliant = "yes";

  default_list = split(set_points, sep:sep, keep:FALSE);

  foreach _setting (default_list){
    _setting = ereg_replace(string:chomp(_setting), pattern:"^\s+", replace:"");
    if(_setting >!< value){
      compliant = "no";
    }
  }

  return(compliant);
}

# @brief Check if items from to lists match exactly
#
# @param value string which needs to contain set_points
# @param set_points list of set points
# @param sep separator in set_points list
#
# @return "yes" if compliant or "no" otherwise
#
function policy_settings_lists_match(value, set_points, sep){
  local_var value, set_points, sep;
  local_var default_list, _setting, value_list;

  default_list = split(set_points, sep:sep, keep:FALSE);
  foreach _setting (default_list){
    _setting = ereg_replace(string:chomp(_setting), pattern:"^\s+", replace:"");
    if(_setting >!< value)
      return("no");
  }

  value_list = split(value, sep:sep, keep:FALSE);
  foreach _setting (value_list){
    _setting = ereg_replace(string:chomp(_setting), pattern:"^\s+", replace:"");
    if(_setting >!< set_points)
      return("no");
  }

  return("yes");
}

# @brief Extract uid from linux stat command
#
# @param stat return string form stat command
#
# @return uid or empty if error
#
function policy_chown_get_uid(stat){
  local_var stat;
  local_var uid;

  uid = eregmatch(string:stat, pattern:"Uid: \(\s+[0-9]+/\s+([^)]+)\)");
  if(!uid)
    return;

  return(uid[1]);
}

# @brief Extract gid from linux stat command
#
# @param stat return string form stat command
#
# @return gid or empty if error
#
function policy_chown_get_gid(stat){
  local_var stat;
  local_var gid;

  gid = eregmatch(string:stat, pattern:"Gid: \(\s+[0-9]+/\s+([^)]+)\)");
  if(!gid)
    return;

  return(gid[1]);
}

# @brief Extract all configuration blocks matching from prefix to suffix in a configuration file (requires Perl and SSH connection)
#
# @param socket for the ssh command
# @param file - path and filename
# @param prefix - match starting from this string
# @param suffix - match ending with this string
# @param grep - Only match string cases within the prefix and suffix (optional)
# @param grep_exclude - Exclude the string from the search (optional)
# @param inverse - Return content not within prefix and suffix as a string (optional)
#
# Note: From optional parameters, only grep and inverse can be used together
#
# @return a string array containing all matching blocks, or a string of the inverse search
#
function policy_get_matching_blocks_linux(socket, file, string, prefix, suffix, grep, grep_exclude, inverse){

  local_var socket, file, string, prefix, suffix, grep, grep_exclude, inverse;
  local_var cmd, value, index, index_string, block_array, line;

  if(grep && !inverse){
    cmd = "perl -ne 'print if /^ *" + prefix + " */i .. /" + suffix + "/i' " + file + " | grep -i '" + grep + "'";
  }else if(inverse && !grep){
    cmd = "perl -ne 'print if !(/^ *" + prefix + " */i .. /" + suffix + "/i)' " + file;
  }else if(inverse && grep){
    cmd = "perl -ne 'print if !(/^ *" + prefix + " */i .. /" + suffix + "/i)' " + file + " | grep -i '" + grep + "'";
  }else if(grep_exclude){
    cmd = "perl -ne 'print if /^ *" + prefix + " */i .. /" + suffix + "/i' " + file + " | grep -v '" + grep_exclude + "'";
  }else{
    cmd = "perl -ne 'print if /^ *" + prefix + " */i .. /" + suffix + "/i' " + file;
  }

  value = ssh_cmd_without_errors(socket:socket, cmd:cmd);
  index = 0;
  index_string = "";
  block_array[0] = "";

  if(inverse){
    return value;
  }else{
    foreach line(split(value)){
      index_string += line;

      if(suffix >< line){
        block_array[index] = index_string;
        index++;
        index_string = "";
      }
    }
    return block_array;
  }
}

# @brief Check all configuration blocks from an array for a string value
#
# @param array string array of configuration blocks
# @param match if only auditing blocks containing string (optional)
# @param must_include configuration to be audited
#
# @return compliance
#
function policy_audit_config_blocks_linux(array, match, must_include){

  local_var array, match, must_include;
  local_var x, compliant, comment;

  x=0;
  if(match){
    while(array[x]){
      if(match){
        if(match >< array[x]){
          if(must_include >!< array[x] ){
            compliant = "no";
            comment += "Not compliant: " + array[x] + '\n';
          }
        }
      }
      x++;
    }
  }else{
    while(array[x]){
      if(must_include >!< array[x] ){
        compliant = "no";
        comment += "Not compliant: " + array[x] + '\n';
      }
      x++;
    }
  }

  if(compliant !~ "no" && compliant !~ "incomplete"){
    compliant = "yes";
  }
  return compliant;
}

# @brief Extract access from linux stat command
#
# @param stat return string form stat command
#
# @return access permissions in four-digit representation
#
function policy_get_access_permissions(stat){
  local_var stat;
  local_var perm;

  if(!stat){
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_get_access_permissions: stat empty");
    return;
  }

  perm = eregmatch(string:stat, pattern:"Access: \([0-9]([0-9]{3})");
  if(!perm)
    return;

  return(perm[1]);
}

# @brief Checks if value permission matches at least permission from set_point
#
# @param value actual access permission (3-digit format)
# @param set_point access permissions to be compliant (3-digit format)
#
# @return "yes" if compliant "no" otherwise
#
function policy_access_permissions_match_or_stricter(value, set_point){
  local_var value, set_point;
  local_var octal_to_filemode, value_filemode, set_point_filemode, compliant, sticky_bit_value, sticky_bit_set_point, i;

  if(!value || !set_point){
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_access_permissions_match_or_stricter: value or set_point empty");
    return;
  }

  value = string(value);
  set_point = string(set_point);

  octal_to_filemode = make_array("0","---","1","--x","2","-w-","3","-wx","4","r--","5","r-x","6","rw-","7","rwx");

  value_filemode = "";
  set_point_filemode = "";
  compliant = "yes";

  # Get sticky bit of value and cut the string
  if(strlen(value) == 4){
    sticky_bit_value = value[0];
    value = substr(value,1);
  }

  # Get sticky bit of set_point and cut the string
  if(strlen(set_point) == 4){
    sticky_bit_set_point = set_point[0];
    set_point = substr(set_point,1);

    # Test sticky bit, if set_point includes sticky bit
    if(sticky_bit_value != sticky_bit_set_point)
      compliant = "no";
  }

  # Convert octal representation to filemode. e.g.: 640 = rw-r-----
  for(i=0; i<3; i++){
    value_filemode += octal_to_filemode[value[i]];
    set_point_filemode += octal_to_filemode[set_point[i]];
  }

  for(i=0; i<9; i++){
    # If each access permission from set point match the actual value OR if the permission is not granted,
    # it is considered as compliant
    # e.g.: set point: rw-r-----
    # actual value: rw-r----- = compliant
    # actual value: r-------- = compliant
    # actual value: rw-r--r-- = not compliant
    # actual value: rw--w---- = not compliant
    # Exact match
    if ( set_point_filemode[i] == value_filemode[i] )
      continue;

    if ( set_point_filemode[i] == "-" && value_filemode[i] != "-" )
      continue;

    # Everything else implies value is less restrictive
    compliant = "no";
  }

  return(compliant);
}

# @brief Build a string from a list
#
# @param list items as list
# @param sep separator for items in string
#
# @return string of concatenated list items
#
function policy_build_string_from_list(list, sep){
  local_var list, sep;
  local_var ret_string, _item;

  ret_string = "";

  foreach _item (list){
    ret_string += sep + _item;
  }

  ret_string = str_replace(string:ret_string, find:sep, replace:"", count:1);

  return(ret_string);
}

# @brief Set kb entry for access permission of a file
#
# @param socket for the ssh command
# @param file to get access permission for
# @param kb_name the (optional) name of the KB item used to save the result
#
function policy_linux_stat_file(socket, file, kb_name){
  local_var socket, file, kb_name, cmd, stat;

  cmd = "stat " + file + " 2>/dev/null";

  stat = ssh_cmd_without_errors(socket:socket, cmd:cmd);

  if(!kb_name)
    kb_name = file;

  if(!stat)
    set_kb_item(name:"Policy/linux/" + kb_name + "/stat/ERROR", value:TRUE);
  else
    set_kb_item(name:"Policy/linux/" + kb_name + "/stat", value:stat);
}

# @brief Set kb entry with content of a file
#
# @param socket for the ssh command
# @param file to read
#
function policy_linux_file_content(socket, file){
  local_var socket, file, cmd, content;

  cmd = "cat " + file + " 2>/dev/null";

  content = ssh_cmd_without_errors(socket:socket, cmd:cmd);

  if(!content)
    set_kb_item(name:"Policy/linux/" + file + "/content/ERROR", value:TRUE);
  else
    set_kb_item(name:"Policy/linux/" + file + "/content", value:content);
}

# @brief Compare two INT variables and return the greater one.
#        If one variable is empty, return the other one.
#
# @param value1 first INT to compare
# @param value2 second INT to compare
#
# @return greater INT
#
function policy_return_greater_value(value1, value2){
  local_var value1, value2;

  if(!value1 && !value2){
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_return_greater_value: value1 and value2 empty");
    return;
  }

  if(!value1)
    return(value2);

  if(!value2)
    return(value1);

  if(int(value1) > int(value2))
    return(value1);

  return(value2);
}

# @brief Compare two INT variables and return the smaller one.
#        If one variable is empty, return the other one.
#
# @param value1 first INT to compare
# @param value2 second INT to compare
#
# @return lower INT
#
function policy_return_smaller_value(value1, value2){
  local_var value1, value2;

  if(!value1 && !value2){
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_return_smaller_value: value1 and value2 empty");
    return;
  }

  if(!value1)
    return(value2);

  if(!value2)
    return(value1);

  if(int(value1) < int(value2))
    return(value1);

  return(value2);
}

# @brief Iterate over files in directory and save content and access rights to KB
#
# @param socket for the ssh command
# @param directory where the files are stored
#
function policy_read_files_in_directory(socket, directory){
  local_var socket, directory, files, _file;

  if(!directory || !socket){
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_read_files_in_directory: directory or socket empty");
  }

  files = ssh_cmd_without_errors(socket:socket, cmd:"ls --format=single-column " + directory);

  if(!files){
    set_kb_item(name:"Policy/linux/" + directory + "/ERROR", value:TRUE);
  }else{
    foreach _file (split(files, keep:FALSE)){
      set_kb_item(name:"Policy/linux/" + directory + "/files/", value:directory + _file);
      policy_linux_stat_file(socket:socket, file:directory + _file);
      policy_linux_file_content(socket:socket, file:directory + _file);
    }
  }
}

# @brief Run SQL query on ZSQL server
#
# @param socket for the ssh command
# @param query to run on server
#
# @return output from query
#
function zsql_command(socket, query){
  local_var socket, query;
  local_var user, password, ip, port, cmd, output;

  if(!user = get_kb_item("Policy/gaussdb/user"))
    user = "SYS";

  if(!password = get_kb_item("Policy/gaussdb/password"))
    password = "Changeme_123";

  if(!ip = get_kb_item("Policy/gaussdb/ip"))
    ip = "127.0.0.1";

  if(!port = get_kb_item("Policy/gaussdb/port"))
    port = "1611";

  cmd = 'zsql ' + user + '/' + password + '@' + ip + ':' + port + ' -q -c "' + query + '"';

  output = ssh_cmd(socket:socket, cmd:cmd, return_errors:FALSE, nosh:TRUE);

  if(!output)
    return;
  else
    return(output);
}

# @brief Run SQL query on MySQL server
#
# @param socket for the ssh command
# @param query to run on server
#
# @return output from query
#
function mysql_command(socket, query){
  local_var socket, query;
  local_var user, password, ip, port, cmd, output;

  if(!user = get_kb_item("Policy/mysql/user"))
    user = "root";

  if(!password = get_kb_item("Policy/mysql/password"))
    password = "";

  if(!ip = get_kb_item("Policy/mysql/ip"))
    ip = "127.0.0.1";

  if(!port = get_kb_item("Policy/mysql/port"))
    port = "3306";

  cmd = 'mysql' + ' --user=' + user + ' --password=' + password + ' --host=' + ip + ' --port=' + port + ' -sN -e "' + query + '"';

  output = ssh_cmd(socket:socket, cmd:cmd, return_errors:FALSE, nosh:TRUE);

  if(!output)
    return;
  else
    return(output);
}

# @brief Run a SQL query on a PostgreSQL server via SSH and a 'psql' command
#
# @param socket The socket for the connection to the remote SSH service.
# @param query  The query to run
#
# @note Please add a dependency to postgresql_compliance_options.nasl if you want to use this
#       function in a VT.
#
# @return The output of the query or NULL if the query / command failed.
#
function psql_command(socket, query){
  local_var socket, query;
  local_var port, username, password, database, cmd, output;

  if(!port = get_kb_item("Policy/PostgreSQL/port"))
    port = "5432";

  username = get_kb_item("Policy/PostgreSQL/username");
  password = get_kb_item("Policy/PostgreSQL/password");
  database = get_kb_item("Policy/PostgreSQL/database");

  # nb: From "man psql":
  # -c: "Specifies that psql is to execute the given command string, command."
  # -p: "Specifies the TCP port or the local Unix-domain socket file extension on which the server is listening for connections."
  # -U: "Connect to the database as the user username instead of the default. (You must have permission to do so, of course.)"
  # -w: "Never issue a password prompt."
  # -d: "Specifies the name of the database to connect to."
  #
  # and from https://www.postgresql.org/docs/current/libpq-envars.html:
  # > PGPASSWORD behaves the same as the password connection parameter.

  if(username && password)
    cmd = "PGPASSWORD=" + password + ' psql -c "' + query + '"' + " -p " + port + " -U " + username;
  else if(username)
    cmd = 'psql -c "' + query + '"' + " -p " + port + " -U " + username + " -w";
  else if(password)
    cmd = "PGPASSWORD=" + password + ' psql -c "' + query + '"' + ' -p ' + port;
  else
    cmd = 'psql -c "' + query + '"' + ' -p ' + port;

  if(database)
    cmd += " -d " + database;

  output = ssh_cmd(socket:socket, cmd:cmd, return_errors:FALSE, nosh:TRUE);

  if(!output)
    return;
  else
    return(output);
}

# @brief Run modprobe -n -v against given module
#
# @param module to test
#
# @return output from command
function policy_modprobe(module){
  local_var module, sock, cmd, ret;

  if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection())
    return;

  cmd = "modprobe -n -v " + module;
  ret = ssh_cmd(socket:sock, cmd:cmd);

  if(!ret) # if module is loaded, modprobe returns nothing
    ret = "none";

  return (ret);
}

# @brief Run SQL query on GSQL (openGauss, GaussDB Kernel) host system
#
# @param socket for the ssh command
# @param query to run on server
#
# @return output from query
#
function policy_gsql_cmd(socket, query, db_type){
  local_var socket, query, db_type;
  local_var database, port, use_su, su_user, cmd, output;

  if(db_type == "gaussdbkernel"){

    if(!database = get_kb_item("Policy/gaussdbkernel/database"))
      database = "postgres";

    if(!port = get_kb_item("Policy/gaussdbkernel/port"))
      port = "8000";

    use_su = get_kb_item("Policy/gaussdbkernel/use_su");
    if(use_su && "yes" >< use_su){
      su_user = get_kb_item("Policy/gaussdbkernel/su_user");
      # Using single quotes for the -c parameter loads the environmental variables
      # of the su user. Using single quotes makes the escaping of them to such a pain.
      cmd = 'gsql -d ' + database + ' -p ' + port + ' -t -c "' + query + '"';
      cmd = str_replace( string:cmd, find:"'", replace:'\'"\'"\'' );

      cmd = "su - " + su_user + " -s /bin/bash -c '" + cmd + "'";
    }else{
      cmd = 'gsql -d ' + database + ' -p ' + port + ' -t -c "' + query + '"';
    }

  }else{

    if(!database = get_kb_item("Policy/opengauss/database"))
      database = "postgres";

    if(!port = get_kb_item("Policy/opengauss/port"))
      port = "26000";

    use_su = get_kb_item("Policy/opengauss/use_su");
    if(use_su && "yes" >< use_su){
      su_user = get_kb_item("Policy/opengauss/su_user");
      # Using single quotes for the -c parameter loads the environmental variables
      # of the su user. Using single quotes makes the escaping of them to such a pain.
      cmd = 'gsql -d ' + database + ' -p ' + port + ' -t -c "' + query + '"';
      cmd = str_replace( string:cmd, find:"'", replace:'\'"\'"\'' );

      cmd = "su - " + su_user + " -s /bin/bash -c '" + cmd + "'";
    }else{
      cmd = 'gsql -d ' + database + ' -p ' + port + ' -t -c "' + query + '"';
    }
  }

  output = ssh_cmd(socket:socket, cmd:cmd, return_errors:TRUE, nosh:TRUE, nosu:TRUE);

  if(!output)
    return;
  else
    return(output);
}


# @brief Convert access permission to octal mode
#
# @param perm access permission in string mode (9 chars)
#
# @return string numeric representation of access permissions
#
function policy_access_permissions_string_to_numeric(perm){
  local_var perm;
  local_var filemode_to_octal, owner, group, other, octal;

  if(!perm){
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_access_permissions_string_to_numeric: perm empty");
    return;
  }

  filemode_to_octal = make_array("---","0","--x","1","-w-","2","-wx","3","r--","4","r-x","5","rw-","6","rwx","7",
    "--S","0","-wS","2","r-S","4","rwS","6", # suid / guid without access perm
    "--s","1","-ws","3","r-s","5","rws","7", # suid / guid with access perm
    "--T","0","-wT","2","r-T","4","rwT","6", # sticky bit without access perm
    "--t","1","-wt","3","r-t","5","rwt","7"); # sticky bit with access perm

  owner = substr(perm, 0, 2);
  group = substr(perm, 3, 5);
  other = substr(perm, 6, 8);

  octal = strcat(filemode_to_octal[owner], filemode_to_octal[group], filemode_to_octal[other]);

  if(octal)
    return(octal);
  else
    return;
}


# @brief Get owner, group and permission for file(s) (filepath with regex)
#
# @param filepath path so run ls command on (can be regex)
# @param socket linux socket to run ssh command on
#
function policy_access_permission_regex(filepath, socket){
  local_var filepath, socket;
  local_var cmd, files, pattern, line, values, perm, file;

  if(!filepath || !socket){
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#policy_access_permission_regex: filepath or socket empty");
    return;
  }

  filepath = ereg_replace(string:filepath, pattern:'\n', replace:" ");

  cmd = "ls -la " + filepath;
  files = ssh_cmd(socket:socket, cmd:cmd, return_errors:TRUE);
  if(files){
    pattern = "[-d]([rwxtTsS-]{9})[^@[:space:]]+\s+[0-9]+\s+([^@[:space:]]+)\s+([^@[:space:]]+).+\s+([^@[:space:]]+)$";
    foreach line (split(files, keep:FALSE)){
      values = eregmatch(string:chomp(line), pattern:pattern);

      if(values){
        perm = policy_access_permissions_string_to_numeric(perm:values[1]);
        file = values[4];

        set_kb_item(name:"Policy/linux/" + file + "/user", value:values[2]);
        set_kb_item(name:"Policy/linux/" + file + "/group", value:values[3]);
        set_kb_item(name:"Policy/linux/" + file + "/perm", value:perm);
      }
    }
  }
}

# @brief Sends a command via an SSH socket to a Huawei VRP device.
#
# @param socket The socket to run the SSH command on.
# @param cmd    The command to send to the target.
#
# @note Since Yunshan (the newest version of VRP) the return string contains the original
#       command sent to the device and a line with the prompt (<FOO>), if the command does
#       not output anything on the host. If a pipe is included in the sent command like:
#
#       display current-configuration | include ntp
#
#       the response looks like e.g.:
#
#       display current-configuration  include ntp
#       <somenumbersandorchars>
#
#       This function takes care of this behavior and removes the returned command so that
#       only the actual / valid output is returned.
#
# @return NULL if the command didn't return anything or not all mandatory parameter got
#         passed, a string with the result of the command otherwise.
#
function policy_vrp_command(socket, cmd){
  local_var socket, cmd;
  local_var check_pattern, ret;

  if(!socket){
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_vrp_command#-#socket");
    return NULL;
  }

  if(!cmd){
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#policy_vrp_command#-#cmd");
    return NULL;
  }

  # Pattern to replace / remove the returned command. See the @note in the function
  # description for more background info.
  #
  # sent command:    "display current-configuration | include ntp"
  # returned output: "display current-configuration  include ntp
  # <somenumbersandorchars>"
  check_pattern = "^" + ereg_replace(string:cmd, pattern:"\|\s*", replace:"\|?\s*") + "\s*<[^>]*>";

  ret = ssh_cmd(socket:socket, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                retry:10, force_reconnect:TRUE, clear_buffer:TRUE);
  if(!ret)
    return NULL;

  ret = ereg_replace(string:ret, pattern:check_pattern, replace:"");
  if(!ret)
    return NULL;

  return(ret);
}
