# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801501");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_cve_id("CVE-2010-1818");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple QuickTime RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Apple QuickTime version 6.5.2 and prior

  Apple QuickTime version 7.6.7 and prior on Windows.");

  script_tag(name:"insight", value:"The flaw is due to error in 'IPersistPropertyBag2::Read()'
  function in 'QTPlugin.ocx'. It allows remote attackers to execute arbitrary
  code via the '_Marshaled_pUnk attribute', which triggers unmarshaling of an
  untrusted pointer.");

  script_tag(name:"solution", value:"Upgrade to version 7.6.8 or later.");

  script_tag(name:"summary", value:"Apple QuickTime is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://reversemode.com/index.php?option=com_content&task=view&id=69&Itemid=1");
  script_xref(name:"URL", value:"http://threatpost.com/en_us/blogs/new-remote-flaw-apple-quicktime-bypasses-aslr-and-dep-083010");
  script_xref(name:"URL", value:"https://www.metasploit.com/redmine/projects/framework/repository/entry/modules/exploits/windows/browser/apple_quicktime_marshaled_punk.rb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.6.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6.8", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
