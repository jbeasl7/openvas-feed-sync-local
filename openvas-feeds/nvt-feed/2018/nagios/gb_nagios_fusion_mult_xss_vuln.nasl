# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813252");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-06-18 15:27:18 +0530 (Mon, 18 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 14:30:00 +0000 (Thu, 02 Aug 2018)");

  script_cve_id("CVE-2018-12501");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Fusion < 4.1.4 Multiple XSS Vulnerabilities");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nagios_fusion_http_detect.nasl");
  script_mandatory_keys("nagios/fusion/detected");

  script_tag(name:"summary", value:"Nagios Fusion is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple cross site scripting flaws exist in an unknown function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to potentially
  inject arbitrary html and script code into the web site.");

  script_tag(name:"affected", value:"Nagios Fusion versions prior to 4.1.4.");

  script_tag(name:"solution", value:"Update to version 4.1.4 or later.");

  script_xref(name:"URL", value:"https://www.nagios.com/downloads/nagios-fusion/change-log");

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

if (version_is_less(version: version, test_version: "4.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
