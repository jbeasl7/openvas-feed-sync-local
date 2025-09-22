# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800390");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1232");
  script_name("Mozilla Firefox XUL Parsing Denial of Service Vulnerability - Linux");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8306");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49521");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause the browser to crash.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0 to 3.0.8.");
  script_tag(name:"insight", value:"Error in browser due to improper parsing of XUL (XML) documents while opening
  a specially-crafted XML document containing long series of start-tags with no
  corresponding end-tags.");
  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to a XUL parsing vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"3.0", test_version2:"3.0.8")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.6.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
