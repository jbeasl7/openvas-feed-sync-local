# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902361");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-1433");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Information Disclosure Vulnerability (Mar 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the error in 'AgentInterface' and
  'CustomerInterface' components, which place cleartext credentials into the session data in the
  database.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain
  sensitive information by reading the _UserLogin and _UserPW fields.");

  script_tag(name:"affected", value:"OTRS prior to version 3.0.6.");

  script_tag(name:"solution", value:"Update to version 3.0.6 or later.");

  script_xref(name:"URL", value:"http://bugs.otrs.org/show_bug.cgi?id=6878");
  script_xref(name:"URL", value:"http://source.otrs.org/viewvc.cgi/otrs/CHANGES?revision=1.1807");

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

if (version_is_less(version: version, test_version: "3.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
