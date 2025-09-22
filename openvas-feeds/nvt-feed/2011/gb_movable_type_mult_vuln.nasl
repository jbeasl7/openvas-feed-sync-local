# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sixapart:movable_type";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902402");
  script_version("2025-02-21T05:37:49+0000");
  script_tag(name:"last_modification", value:"2025-02-21 05:37:49 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-3921", "CVE-2010-3922", "CVE-2010-4509", "CVE-2010-4511");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Movable Type Multiple Vulnerabilities (Apr 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_movable_type_http_detect.nasl");
  script_mandatory_keys("sixapart/movabletype/detected");

  script_tag(name:"summary", value:"Movable Type is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are caused by input validation errors related to
  'mt:AssetProperty' and 'mt:EntryFlag' tags and in dynamic publishing error messages, which could
  be exploited to conduct SQL injection (SQLi) or cross-site scripting (XSS) attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain knowledge
  of sensitive information or inject SQL queries.");

  script_tag(name:"affected", value:"Movable Type version 4.x prior to 4.35 and 5.x prior to
  5.04");

  script_tag(name:"solution", value:"Update to version 4.35, 5.04 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42539");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45250");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45253");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45380");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45383");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3145");
  script_xref(name:"URL", value:"http://www.movabletype.org/documentation/appendices/release-notes/movable-type-504-435-release-notes.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.34") ||
    version_in_range(version: version, test_version: "5.0", test_version2: "5.03")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.35 / 5.04", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
