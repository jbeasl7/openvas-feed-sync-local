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
  script_oid("1.3.6.1.4.1.25623.1.0.109404");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-06-26 10:31:17 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Require additional authentication at startup (BitLocker without TPM)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1", id:1);

  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to configure whether BitLocker
requires additional authentication each time the computer starts and whether you are using BitLocker
with or without a Trusted Platform Module (TPM). This policy setting is applied when you turn on
BitLocker.

Note: Only one of the additional authentication options can be required at startup, otherwise a
policy error occurs.

If you want to use BitLocker on a computer without a TPM, select the 'Allow BitLocker without a
compatible TPM' check box. In this mode either a password or a USB drive is required for start-up.
When using a startup key, the key information used to encrypt the drive is stored on the USB drive,
creating a USB key. When the USB key is inserted the access to the drive is authenticated and the
drive is accessible. If the USB key is lost or unavailable or if you have forgotten the password
then you will need to use one of the BitLocker recovery options to access the drive.

On a computer with a compatible TPM, four types of authentication methods can be used at startup to
provide added protection for encrypted data. When the computer starts, it can use only the TPM for
authentication, or it can also require insertion of a USB flash drive containing a startup key, the
entry of a 6-digit to 20-digit personal identification number (PIN), or both.

If you enable this policy setting, users can configure advanced startup options in the BitLocker
setup wizard.

If you disable or do not configure this policy setting, users can configure only basic options on
computers with a TPM.

Note: If you want to require the use of a startup PIN and a USB flash drive, you must configure
BitLocker settings using the command-line tool manage-bde instead of the BitLocker Drive Encryption
setup wizard.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Require additional authentication at startup (BitLocker without TPM)";
solution = "Set following UI path accordingly:
Windows Components/BitLocker Drive Encryption/Operating System Drives/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\FVE";
item = "EnableBDEWithNoTPM";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
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
