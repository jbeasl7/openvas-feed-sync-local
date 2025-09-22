# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103962");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2014-01-06 11:30:32 +0700 (Mon, 06 Jan 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CPE Policy Check");
  # nb: Needs to be in ACT_END because cpe_inventory.nasl is also there
  script_category(ACT_END);
  script_family("Policy");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("cpe_inventory.nasl", "compliance_tests.nasl");
  script_mandatory_keys("cpe_inventory/available");

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/compliance-and-special-scans.html#performing-cpe-based-checks");

  script_add_preference(name:"Single CPE", type:"entry", value:"cpe:/", id:1);
  script_add_preference(name:"CPE List", type:"file", value:"", id:2);
  script_add_preference(name:"Check for", type:"radio", value:"present;missing", id:3);

  script_tag(name:"summary", value:"This VT is running CPE-based Policy Checks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

# CPE's registered as host details
cpes = host_details_cpes();

single_cpe = script_get_preference("Single CPE", id:1);

if (!single_cpe || strlen(single_cpe) < 6) {
  cpes_list = script_get_preference_file_content("CPE List", id:2);
  if (!cpes_list) {
    cpes_list = script_get_preference("CPE List");
    if (!cpes_list)
      exit(0);

    sep = ";";
  } else {
    sep = '\n';
  }

  mycpes_split = split(cpes_list, sep:sep, keep:FALSE);
  mycpes = make_list();

  i = 0;
  foreach mcpe (mycpes_split) {
    # Use get_base_cpe() from host_details.inc to verify the correct syntax of the passed CPE
    if (get_base_cpe(cpe:mcpe)) {
      mycpes[i] = mcpe;
      i++;
    } else {
      set_kb_item(name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#main code#-#" + mcpe + "#-#mcpe");
      set_kb_item(name:"policy/cpe/invalid_list", value:mcpe);
      set_kb_item(name:"policy/cpe/invalid_line/found", value:TRUE);
    }
  }
} else {
  # Use get_base_cpe() from host_details.inc to verify the correct syntax of the passed CPE
  if (get_base_cpe(cpe:single_cpe)) {
    mycpes = make_list(single_cpe);
  } else {
    set_kb_item(name:"vt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#main code#-#" + single_cpe + "#-#single_cpe");
    set_kb_item(name:"policy/cpe/invalid_list", value:single_cpe);
    set_kb_item(name:"policy/cpe/invalid_line/found", value:TRUE);
  }
}

if (!mycpes)
  exit(0);

foreach mycpe (mycpes) {
  found = FALSE;
  foreach cpe (cpes) {
    # Present or possibly present
    if (strlen(cpe) >= strlen(mycpe)) {
      if (ereg(pattern:mycpe, string:cpe)) {
        present += string(mycpe, "|", cpe, "\n");
      }
    } else {
      if (ereg(pattern:cpe, string:mycpe)) {
        poss_present += string(mycpe, "|", cpe, "\n");
      }
    }

    # Missing
    if (!ereg(pattern: "^" + mycpe, string: cpe) && found == FALSE) {
      found = FALSE;
    } else {
      found = TRUE;
    }
  }

  if (!found) {
    missing += string(mycpe, "\n");
  }
}

checkfor = script_get_preference("Check for", id:3);
set_kb_item(name:"policy/cpe/checkfor", value:checkfor);

if (present) {
  set_kb_item(name:"policy/cpe/present", value:present);
}

if (poss_present) {
  set_kb_item(name:"policy/cpe/possibly_present", value:poss_present);
}

if (missing) {
  set_kb_item(name:"policy/cpe/missing", value:missing);
}

exit(0);
