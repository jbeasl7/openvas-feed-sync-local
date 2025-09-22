# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109102");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-04-23 15:29:04 +0200 (Mon, 23 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Join Microsoft MAPS");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1", id:1);

  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to join Microsoft MAPS. Microsoft
MAPS is the online community that helps you choose how to respond to potential threats. The
community also helps stop the spread of new malicious software infections.

You can choose to send basic or additional information about detected software. Additional
information helps Microsoft create new definitions and help it to protect your computer. This
information can include things like location of detected items on your computer if harmful software
was removed. The information will be automatically collected and sent. In some instances, personal
information might unintentionally be sent to Microsoft. However, Microsoft will not use this
information to identify you or contact you.

Possible options are:

  - 0: Disabled (default)

  - 1: Basic membership

  - 2: Advanced membership

Basic membership will send basic information to Microsoft about software that has been detected,
including where the software came from, the actions that you apply or that are applied automatically,
and whether the actions were successful.

Advanced membership, in addition to basic information, will send more information to Microsoft about
malicious software, spyware, and potentially unwanted software, including the location of the
software, file names, how the software operates, and how it has impacted your computer.

If you enable this setting, you will join Microsoft MAPS with the membership specified.

If you disable or do not configure this setting, you will not join Microsoft MAPS.

In Windows 10, Basic membership is no longer available, so setting the value to 1 or 2 enrolls the
device into Advanced membership.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Join Microsoft MAPS";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Windows Components/
Windows Defender/MAPS/" + title;
test_type = "RegKey";
type = "HKLM";
key = "SOFTWARE\Policies\Microsoft\Windows Defender\Spynet";
item = "SpyNetReporting";
reg_path = type + "\" + key + "!" + item;
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);