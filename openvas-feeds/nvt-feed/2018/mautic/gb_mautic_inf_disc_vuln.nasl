# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mautic:mautic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113162");
  script_version("2024-10-22T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"creation_date", value:"2018-04-19 13:45:35 +0200 (Thu, 19 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-23 14:41:00 +0000 (Wed, 23 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10189");

  script_name("Mautic <= 2.12 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mautic_http_detect.nasl");
  script_mandatory_keys("mautic/detected");

  script_tag(name:"summary", value:"Mautic is prone to an information disclosure vulnerability via
  cookie manipulation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to systematically emulate tracking cookies per
  contact due to tracking the contact by their auto-incremented ID. Thus, a third party can
  manipulate the cookie value with +1 to systematically assume being tracked as each contact in
  Mautic. It is then possible to retrieve information about the contact through forms that have
  progressive profiling enabled.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access
  information about another user.");

  script_tag(name:"affected", value:"Mautic versions through 2.12.");

  script_tag(name:"solution", value:"Update to version 2.13.0 or later.");

  script_xref(name:"URL", value:"https://github.com/mautic/mautic/releases/tag/2.13.0");

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

if (version_is_less(version: version, test_version: "2.13.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.13.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
