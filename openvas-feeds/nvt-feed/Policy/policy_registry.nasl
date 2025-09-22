# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105988");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2015-05-22 12:17:31 +0700 (Fri, 22 May 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Registry Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_registry_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_access");
  script_add_preference(name:"Policy registry file", type:"file", value:"", id:1);
  script_add_preference(name:"Run as policy", type:"checkbox", value:"no", id:2);

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/compliance-and-special-scans.html#checking-registry-content");

  script_tag(name:"summary", value:"Checks the presens of specified Registry keys and values on Windows.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

reglist = script_get_preference("Policy registry file", id:1);
if (!reglist)
  exit(0);

reglist = script_get_preference_file_content("Policy registry file", id:1);
if (!reglist)
  exit(0);

valid_lines_list = make_list();

set_kb_item(name:"policy/registry/started", value:TRUE);

lines = split(reglist, keep:FALSE);
line_count = max_index(lines);

if (line_count == 1 && lines[0] == "Present|Hive|Key|Value|ValueType|ValueContent") {
  set_kb_item(name:"policy/registry/general_error_list", value:"Attached registry File doesn't contain test entries (Only the header is present).");
  exit(0);
}

x = 0;
foreach line (lines) {
  x++;
  if (!eregmatch(pattern:"(TRUE|FALSE)\|(HKLM|HKCU)\|([a-zA-Z0-9\\]+)\|.*\|(REG_DWORD|REG_SZ|REG_BINARY)\|.*", string:line) &&
      !eregmatch(pattern:"(TRUE|FALSE)\|(HKLM|HKCU)\|([a-zA-Z0-9\\]+)", string:line) &&
      line != "Present|Hive|Key|Value|ValueType|ValueContent"){
    if (x == line_count && eregmatch(pattern:"^$", string:line))
      continue; # accept one empty line at the end of registry list.
    set_kb_item(name:"policy/registry/invalid_list", value:line + "|invalid line error|error;");
    error = TRUE;
    error_list += line + '\n';
    continue;
  }
  # Ignore the header of the checksum file
  if (line != "Present|Hive|Key|Value|ValueType|ValueContent")
    valid_lines_list = make_list (valid_lines_list, line);
}

for (i=0; i<max_index(valid_lines_list); i++) {
  val = split(valid_lines_list[i], sep:"|", keep:FALSE);
  present = tolower(val[0]);
  hive = val[1];
  key = val[2];
  if (max_index(val) == 6) {
    value = val[3];
    type = val[4];
    content = val[5];
  }

  # Just check if registry key exists
  if (max_index(val) < 6) {
    key_exists = registry_key_exists(key:key, type:hive);
    if (((present == "true") && key_exists) ||
        ((present == "false") && !key_exists)){
      set_kb_item(name:"policy/registry/ok_list", value:hive + '\\' + key + ' | ' + present);
      ok_list += hive + '\\' + key + ': ' + present + '\n';
    }else{
      if (((present == "true") && !key_exists) ||
          ((present == "false") && key_exists)){
        set_kb_item(name:"policy/registry/violation_list", value:hive + '\\' + key + ' | ' + present);
        failed = TRUE;
        failed_list += hive + '\\' + key + ': ' + present + '\n';
      }
    }
  }
  else {
    if (type == "REG_DWORD")
      reg_content = registry_get_dword(key:key, item:value, type:hive);
    else if (type == "REG_SZ")
      reg_content = registry_get_sz(key:key, item:value, type:hive);
    else if (type == "REG_BINARY")
      reg_content = registry_get_binary(key:key, item:value, type:hive);

    #nb: REG_DWORD might also return a numeric 0 so checking for !isnull() in this special case
    if (type == "REG_DWORD" && !isnull(reg_content) && content == "*" && present == "true") {
      set_kb_item(name:"policy/registry/ok_list", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' + content + ' | ' + reg_content);
      ok_list += hive + '\\' + key + '\\' + value + ': ' + reg_content + '\n';
    } else if (type == "REG_DWORD" && !isnull(reg_content) && content == "*" && present == "false") {
      set_kb_item(name:"policy/registry/violation_list", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' + content + ' | ' + reg_content);
      failed = TRUE;
      failed_list += hive + '\\' + key + '!' + value + ': ' + reg_content + '\n';
    } else if (reg_content && content == "*" && present == "true") {
      set_kb_item(name:"policy/registry/ok_list", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' + content + ' | ' + reg_content);
      ok_list += hive + '\\' + key + '\\' + value + ': ' + reg_content + '\n';
    } else if (reg_content && content == "*" && present == "false") {
      set_kb_item(name:"policy/registry/violation_list", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' + content + ' | ' + reg_content);
      failed = TRUE;
      failed_list += hive + '\\' + key + '!' + value + ': ' + reg_content + '\n';
    } else if ((reg_content == content && present == "true") ||
               (reg_content != content && present == "false")) {
      set_kb_item(name:"policy/registry/ok_list", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' + content + ' | ' + reg_content);
      ok_list += hive + '\\' + key + '\\' + value + ': ' + reg_content + '\n';
    }
    else {
      if ((reg_content == content && present == "false") ||
          (reg_content != content && present == "true")) {
        set_kb_item(name:"policy/registry/violation_list", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' + content + ' | ' + reg_content);
        failed = TRUE;
        failed_list += hive + '\\' + key + '!' + value + ': ' + reg_content + '\n';
      }
    }
  }
}

run_as_policy = script_get_preference("Run as policy", id:2);
if(run_as_policy == "yes"){
  set_kb_item(name:"Compliance/verbose", value:TRUE);

  solution = "Set registry keys as defined";
  type = "RegKey";
  test = "Multiple RegKeys";

  value = "Following tests did not pass the test: ";
  value += failed_list;
  value += '\nFollowing tests passed the test: ';
  value += ok_list;
  value += '\nFollowing tests are not valid: ';
  value += error_list;

  if(failed){
    compliant = "no";
  }else if(error){
    compliant = "incomplete";
  }else{
    compliant = "yes";
  }

  policy_reporting(result:value, default:reglist, compliant:compliant, fixtext:solution, type:type, test:test);
}

exit(0);
