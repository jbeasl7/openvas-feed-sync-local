# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:jabber";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805712");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2015-4218");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-07-03 11:19:11 +0530 (Fri, 03 Jul 2015)");
  script_name("Cisco Jabber Information Disclosure Vulnerability (Jun 2015) - Windows");

  script_tag(name:"summary", value:"Cisco Jabber is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  validation of GET parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Cisco Jabber versions through
  9.6(3) and 9.7 through 9.7(5) Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=39494");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_jabber_detect_win.nasl");
  script_mandatory_keys("Cisco/Jabber/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jbVer = get_app_version(cpe:CPE)){
  exit(0);
}

#Removing Build from Version
jbVer = ereg_replace(string:jbVer, pattern:".[0-9][0-9]+", replace:"");
if(!jbVer){
  exit(0);
}

if(version_in_range(version:jbVer, test_version:"9.6.0", test_version2:"9.6.3")||
   version_in_range(version:jbVer, test_version:"9.7.0", test_version2:"9.7.5"))
{
   report = 'Installed version: ' + jbVer + '\n' +
           'Fixed version:     WillNotFix \n';
   security_message(data:report);
   exit(0);
}
