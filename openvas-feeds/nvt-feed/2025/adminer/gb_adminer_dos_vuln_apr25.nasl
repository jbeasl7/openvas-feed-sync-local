# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adminer:adminer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155221");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-27 05:40:06 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-43960");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adminer <= 4.8.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_adminer_http_detect.nasl");
  script_mandatory_keys("adminer/detected");

  script_tag(name:"summary", value:"Adminer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When using Monolog for logging, Adminer allows a denial of
  service (memory consumption) via a crafted serialized payload (e.g., using s:1000000000),
  leading to a PHP Object Injection issue.");

  script_tag(name:"impact", value:"Remote, unauthenticated attackers can trigger this by sending a
  malicious serialized object, which forces excessive memory usage, rendering Adminer's interface
  unresponsive and causing a server-level DoS. While the server may recover after several minutes,
  multiple simultaneous requests can cause a complete crash requiring manual intervention.");

  script_tag(name:"affected", value:"Adminer version 4.8.1 and prior.");

  script_tag(name:"solution", value:"Update to version 4.8.2 or later.");

  script_xref(name:"URL", value:"https://github.com/far00t01/CVE-2025-43960");

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

if (version_is_less_equal(version: version, test_version: "4.8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
