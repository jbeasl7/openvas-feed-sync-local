# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800406");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0071");
  script_name("Mozilla Firefox designMode Null Pointer Dereference DoS Vulnerability - Linux");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0220.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33154");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0223.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-01/0224.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_tag(name:"impact", value:"Successful remote exploitation could result in denying the service.");

  script_tag(name:"affected", value:"Mozilla Firefox version 3.x to 3.0.5.");

  script_tag(name:"insight", value:"Null pointer dereferencing error occurs in the browser which fails to validate
  the user input data when designMode module is enabled. These can be exploited
  via replaceChild or removeChild call, followed by a queryCommandValue,
  queryCommandState or queryCommandIndeterm call.");

  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a denial of service (DoS) vulnerability.");

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

if(version_in_range(version:version, test_version:"3.0", test_version2:"3.0.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.6.3", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
