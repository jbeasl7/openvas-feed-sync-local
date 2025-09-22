# Copyright (C) 2014 Greenbone Networks GmbH
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


# @brief reporting function for IT-Grundschutz Kataloge (old IT-Grundschutz)
#
# @param itg_id the id if the requirement
#
# @return NULL
#
function itg_send_details(itg_id) {

  local_var itg_id;
  local_var result, desc, report;

  if(!itg_id) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#itg_id#-#itg_send_details");
    return;
  }

  result = get_kb_item(string(itg_id + "/result"));
  desc = get_kb_item(string(itg_id + "/desc"));

  report = 'Ergebnis:\t' + result +
           '\nDetails:\t' + desc + '\n\n';

  log_message(port:0, proto:"IT-Grundschutz", data:report);
}

# @brief deprecated reporting function (for new IT-grundschutz). Can be removed, once
#        each requirement has own VT (e.g. SYS.2.2.3.A1)
#
# @param oid oid from the policy control (with list result)
# @param requirement default value as stated in policy
# @param status_spec default value (enabled or disabled)
#
# @return array with results, title and fixtext
#
function itg_report_list(oid, requirement, status_spec) {

  local_var oid, requirement, status_spec;
  local_var results, title, result, _id, not_compliant;

  results = get_kb_list("1.3.6.1.4.1.25623.1.0." + oid + "/RESULT/*");
  title = get_kb_item("1.3.6.1.4.1.25623.1.0." + oid + "/NAME");

  if(!results) {
    result["Status"] = "Fehler";
  } else {
    foreach _id(keys(results)) {
      if(results[_id] != requirement) {
        not_compliant = TRUE;
      }
    }
    if(not_compliant) {
      result["Status"] = "Nicht erfuellt";
    } else {
      result["Status"] = "Erfuellt";
    }
  }
  result['Titel'] = '"' + title + '" sollte ' + status_spec + ' werden';
  return result;
}

# @brief reporting for one policy control
#
# @param oid oid from the policy control (with one result, not list)
# @param requirement default value as stated in policy
# @param status_spec default value (enabled or disabled)
#
# @return array with results, title and fixtext
#
function itg_report_item(oid, requirement, status_spec) {

  local_var oid, requirement, status_spec;
  local_var results, title, result;

  results = get_kb_item("1.3.6.1.4.1.25623.1.0." + oid + "/RESULT");
  title = get_kb_item("1.3.6.1.4.1.25623.1.0." + oid + "/NAME");

  if(!results) {
    result['Status'] = 'Fehler';
  } else if(results != requirement) {
    result['Status'] = 'Erfuellt';
  } else {
    result['Status'] = 'Nicht erfuellt';
  }
  result['Titel'] = '"' + title + '" sollte ' + status_spec + ' werden';
  return result;
}

# @brief reporting function for new IT-Grundschutz
#
# @param report string matching Greenbone Compliance Report format
#
# @return NULL
#
function itg_report(report) {

  local_var report;

  if(!get_kb_item("GSHB/silence"))
     log_message(data:report, port:0, proto:"Policy/Control");
}

# @brief checks if level of IT-Grundschutz requirement matches
#        given level so if it should be started
#
# @param level the level of the IT-Grundschutz requirement
#
# @return bool TRUE if requirement should be started, FALSE if not
#
function itg_start_requirement(level) {

  local_var level;
  local_var ITGLevel, selected_level;

  ITGLevel = get_kb_item("GSHB/level");
  if(ITGLevel == "Basis") {
    selected_level = 0;
  } else if(ITGLevel == "Standard") {
    selected_level = 1;
  } else {
    selected_level = 2;
  }

  if(level == "Basis") {
    level = 0;
  }else if(level == "Standard") {
    level = 1;
  }else{
    level = 2;
  }

  if(level <= selected_level) {
    return TRUE;
  }
  return FALSE;
}

# @brief creates the report for each Policy Control for the ITG Anforderung
#
# @param oid_list list of all Policy Controls included
#
# @return array with keys itg_detail_report, which is the detailed report for each Policy Control.
#         desc is the description as set for summary vt, compliant is the compliance status.
#
function itg_get_policy_control_result(oid_list){
  local_var oid_list;
  local_var compliant, _oid, kb_compliant, solution, test, kb_note, notes, ret;

  compliant = "yes";

  foreach _oid (oid_list){
    kb_compliant = get_kb_item(_oid + "/COMPLIANT");
    if (tolower(kb_compliant) != "yes"){
      solution += "; " + _oid + ": " + get_kb_item(_oid + "/FIX");
      if(kb_compliant == "incomplete" && compliant != "no"){
        compliant = "incomplete";
      }else if(kb_compliant == "no"){
        compliant = "no";
      }
    }
    test += "; " + _oid + ": " + get_kb_item(_oid + "/CMD");
    if (kb_note = get_kb_item(_oid + "/NOTE")){
      notes += "; " + _oid + ": " + kb_note;
    }
  }

  if (notes)
    notes = str_replace(string:notes, find:"; ", replace:"", count:1);
  else
    notes = "";

  if (solution)
    solution = str_replace(string:solution, find:"; ", replace:"", count:1);
  else
    solution = "";

  if (test)
    test = str_replace(string:test, find:"; ", replace:"", count:1);
  else
    test = "";

  ret = make_array("compliant", compliant, "solutions", solution, "tests", test, "notes", notes);

  return(ret);
}

# @brief set kb entries needed for summary VT GSHB/GSHB_Kompendium.nasl
#
# @param result overall result from all Policy Controls
# @param desc more detailed explanation for the result
# @param title of IT-Grundschutz Anforderung
# @param id of IT-Grundschutz Anforderung
#
# @return NULL
#
function itg_set_kb_entries(result, desc, title, id){
  local_var result, desc, title, id;

  set_kb_item(name:"GSHB/" + string(id) + "/result", value:result);
  set_kb_item(name:"GSHB/" + string(id) + "/desc", value:desc);
  set_kb_item(name:"GSHB/" + string(id) + "/title", value:title);
}


# @brief returns german result string for not correct target
#
# @param NULL
#
# @return string for not correct target
#
function itg_result_wrong_target(){
  return("nicht zutreffend");
}

# @brief returns german desc string for not correct target
#
# @param NULL
#
# @return string for not correct target
#
function itg_desc_wrong_target(){
  return("Die Anforderung trifft nicht auf das Zielsystem zu.");
}

# @brief returns german string for no test implementable
#
# @param NULL
#
# @return string for not implementable requirement
#
function itg_no_automatic_test(){
  return("Diese Vorgabe muss manuell ueberprueft werden.");
}

# @brief translates compliant string to ITG wording
#
# @param compliant string with compliance status (yes, no, incomplete)
#
# @return string with ITG wording (erfuellt, nicht erfuellt, fehler)
#
function itg_translate_result(compliant){
  local_var compliant, result;

  if(compliant == "yes")
    result = "erfuellt";
  else if(compliant == "incomplete")
    result = "Fehler";
  else
    result = "nicht erfuellt";

  return (result);
}
