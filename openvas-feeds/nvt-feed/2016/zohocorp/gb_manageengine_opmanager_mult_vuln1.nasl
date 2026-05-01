# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106402");
  script_version("2026-04-22T06:16:44+0000");
  script_tag(name:"last_modification", value:"2026-04-22 06:16:44 +0000 (Wed, 22 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-11-22 11:33:23 +0700 (Tue, 22 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ManageEngine OpManager <= 12.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_opmanager_consolidation.nasl");
  script_mandatory_keys("manageengine/opmanager/detected");

  script_tag(name:"summary", value:"ManageEngine OpManager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in ManageEngine OpManager:

  - Denial of Service: When certain characters are in the EncryptPassword value the server process
  will go into an infinite loop.

  - Multiple Cross-Site Scripting vulnerabilities: The User Defined DNS Names table in System
  Settings -> DNS fails to sanitize user input. The ping and traceroute buttons on the
  MonitoringDevice page fail to sanitize the name of the host being monitored.");

  script_tag(name:"impact", value:"A unauthenticated attacker may conduct a denial of service
  condition. Unauthenticated attackers may inject web script or HTML and steal sensitive data and
  credentials.");

  script_tag(name:"affected", value:"ManageEngine OpManager version 12.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Nov/70");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "12.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None available", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
