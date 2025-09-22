# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800713");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1586");
  script_name("GrabIt Stack Based Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34807");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8612");
  script_xref(name:"URL", value:"http://www.shemes.com/index.php?p=whatsnew");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_grabit_detect.nasl");
  script_mandatory_keys("GrabIt/Ver");
  script_tag(name:"affected", value:"GrabIt version 1.7.2 Beta 3 and prior.");
  script_tag(name:"insight", value:"This flaw is due to a boundary check error when processing the DOCTYPE
  declaration within '.NZB' files.");
  script_tag(name:"solution", value:"Upgrade to the latest version 1.7.2 Beta 4.");
  script_tag(name:"summary", value:"GrabIt is prone to stack-based buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause stack overflow by
  crafting an 'NZB' file containing an overly large string as DTD URI.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

grabitVer = get_kb_item("GrabIt/Ver");
if(!grabitVer)
  exit(0);

if(version_is_less(version:grabitVer, test_version:"1.7.2.4")){
  report = report_fixed_ver(installed_version:grabitVer, fixed_version:"1.7.2.4");
  security_message(port: 0, data: report);
}
