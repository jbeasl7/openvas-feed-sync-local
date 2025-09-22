# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800159");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4606");
  script_name("South River Technologies WebDrive Local Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37083/");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_south_river_priv.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507323/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_south_river_webdrive_detect.nasl");
  script_mandatory_keys("SouthRiverWebDrive/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the local attacker to execute arbitrary
  commands with an elevated privileges.");
  script_tag(name:"affected", value:"South River WebDrive version 9.02 build 2232 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to the WebDrive Service being installed without
  security descriptors, which could be exploited by local attackers to,

  - stop the service via the stop command

  - restart the service via the start command

  - execute arbitrary commands with elevated privileges by changing the
    service 'binPath' configuration.");
  script_tag(name:"solution", value:"Upgrade to South River WebDrive version 9.10 or later");
  script_tag(name:"summary", value:"South River Technologies WebDrive is prone to a local privilege escalation vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.webdrive.com/download/index.html");
  exit(0);
}


include("version_func.inc");

webDriveVer = get_kb_item("SouthRiverWebDrive/Win/Ver");
if(webDriveVer != NULL)
{
  if(version_is_less_equal(version:webDriveVer, test_version:"9.02.2232")){
    report = report_fixed_ver(installed_version:webDriveVer, vulnerable_range:"Less than or equal to 9.02.2232");
    security_message(port: 0, data: report);
  }
}
