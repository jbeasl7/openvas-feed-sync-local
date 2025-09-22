# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:soplanning:soplanning";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113741");
  script_version("2025-03-21T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2020-08-12 08:47:03 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 17:04:00 +0000 (Thu, 13 Aug 2020)");

  script_cve_id("CVE-2020-15597");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SOPlanning <= 1.46.01 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_soplanning_http_detect.nasl");
  script_mandatory_keys("soplanning/detected");

  script_tag(name:"summary", value:"SOPlanning is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploitable via the Project Name, Statutes
  Comment, Places Comment, or Resources Comment field.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"SOPlanning through version 1.46.01.");

  script_tag(name:"solution", value:"Update to version 1.47 or later.");

  script_xref(name:"URL", value:"https://www.sevenlayers.com/index.php/364-soplanning-v1-46-01-xss-session-hijack");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.47", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
