# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902549");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_cve_id("CVE-2011-2300");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Oracle VirtualBox Unspecified Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  script_xref(name:"URL", value:"http://securitytracker.com/id/1025805");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48793");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujuly2011.html");

  script_tag(name:"impact", value:"Successful exploitation allows local users to affect confidentiality,
  integrity and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle VirtualBox version 4.0");

  script_tag(name:"insight", value:"The flaw is due to unspecified error related to 'Guest Additions for
  Windows' sub component.");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"solution", value:"Apply the patch.");

  script_tag(name:"qod", value:"30");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_equal(version:version, test_version:"4.0.0")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Equal to 4.0.0", fixed_version:"Apply the patch", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
