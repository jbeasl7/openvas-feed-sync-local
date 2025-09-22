# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805772");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-10-30 10:45:47 +0530 (Fri, 30 Oct 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-7604");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk 6.2.x < 6.2.6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/detected");

  script_tag(name:"summary", value:"Splunk is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XSS due to improper validation of user-supplied input passed
  via unspecified vectors before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server.");

  script_tag(name:"affected", value:"Splunk version 6.2.x prior to 6.2.6.");

  script_tag(name:"solution", value:"Update to version 6.2.6 or later.");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAPAM");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033655");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "6.2.0", test_version2: "6.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
