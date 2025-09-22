# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:diagnostics_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802053");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-3278");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-22 13:07:18 +0530 (Wed, 22 May 2013)");
  script_name("HP Diagnostics Server Message Packet Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_hp_diagnostics_server_detect.nasl");
  script_mandatory_keys("hp/diagnostics_server/detected");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55159");
  script_xref(name:"URL", value:"https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03645497");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"HP Diagnostics Server 8.x through 8.07 and 9.x through 9.21.");

  script_tag(name:"insight", value:"The flaw is due to an error within the magentservice.exe process when
  parsing crafted message packets sent to TCP port 23472.");

  script_tag(name:"summary", value:"HP Diagnostics Server is prone to stack based buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Apply vendor supplied patch.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^[89]\.") {
  if(version_in_range(version:vers, test_version:"8.00", test_version2:"8.07") ||
     version_in_range(version:vers, test_version:"9.00", test_version2:"9.21")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
