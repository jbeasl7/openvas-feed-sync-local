# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rconfig:rconfig";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143640");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-03-26 03:09:37 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-26 15:17:00 +0000 (Thu, 26 Mar 2020)");

  script_cve_id("CVE-2020-10879");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("rConfig < 3.9.5 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to an authenticated remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"rConfig allows command injection by sending a crafted GET request to
  lib/crud/search.crud.php since the nodeId parameter is passed directly to the exec function without being escaped.");

  script_tag(name:"affected", value:"rConfig version 3.9.4 and prior.");

  script_tag(name:"solution", value:"Update to version 3.9.5 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/48241");
  script_xref(name:"URL", value:"https://github.com/rconfig/rconfig/commit/3385f906427d228c48b914625136bf620f4ca0a9");

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

if (version_is_less(version: version, test_version: "3.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
