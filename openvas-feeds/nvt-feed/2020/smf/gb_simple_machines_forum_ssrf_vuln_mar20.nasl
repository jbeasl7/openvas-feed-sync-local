# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:simplemachines:smf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113656");
  script_version("2025-07-22T05:43:35+0000");
  script_tag(name:"last_modification", value:"2025-07-22 05:43:35 +0000 (Tue, 22 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-03-24 10:22:42 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-25 13:22:00 +0000 (Wed, 25 Mar 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11574");

  script_name("Simple Machines Forum (SMF) < 2.0.17 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_http_detect.nasl");
  script_mandatory_keys("smf/detected");

  script_tag(name:"summary", value:"Simple Machines Forum (SMF) is prone to a server-side request
  forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploitable via Subs-Package.php and
  Subs.php because user-supplied data is used directly in curl calls.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary code on the target machine.");

  script_tag(name:"affected", value:"SMF versions through 2.0.16.");

  script_tag(name:"solution", value:"Update to version 2.0.17 or later.");

  script_xref(name:"URL", value:"https://pastebin.com/raw/prE3iiLm");

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

if (version_is_less(version: version, test_version: "2.0.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
