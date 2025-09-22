# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkmk:checkmk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147861");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-03-29 03:15:14 +0000 (Tue, 29 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 15:51:00 +0000 (Mon, 04 Apr 2022)");

  script_cve_id("CVE-2021-40904");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk 1.5.x - 1.5.0p25 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_checkmk_server_http_detect.nasl");
  script_mandatory_keys("checkmk/server/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The web management console allows a misconfiguration of the
  web-app Dokuwiki (installed by default) which allows embedded php code. As a result, remote code
  execution is achieved. Successful exploitation requires access to the web management interface,
  either with valid credentials or with a hijacked session by a user with the role of
  administrator.");

  script_tag(name:"affected", value:"Checkmk version 1.5.0 through 1.5.0p25.");

  script_tag(name:"solution", value:"Update to version 1.6.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Edgarloyola/CVE-2021-40904");

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

if (version_in_range(version: version, test_version: "1.5.0", test_version2: "1.5.0p25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
