# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adminer:adminer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124056");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-04-06 18:14:20 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 20:47:00 +0000 (Tue, 12 Apr 2022)");

  script_cve_id("CVE-2021-43008");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adminer 1.12.0 - 4.6.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adminer_http_detect.nasl");
  script_mandatory_keys("adminer/detected");

  script_tag(name:"summary", value:"Adminer is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Adminer allows an attacker to read arbitrary files on the
  remote server by requesting Adminer to connect to a remote MySQL database.");

  script_tag(name:"affected", value:"Adminer version 1.12.0 through 4.6.2.");

  script_tag(name:"solution", value:"Update to version 4.6.3 or later.");

  script_xref(name:"URL", value:"https://github.com/vrana/adminer/releases/tag/v4.6.3");
  script_xref(name:"URL", value:"https://podalirius.net/en/cves/2021-43008/");
  script_xref(name:"URL", value:"https://sansec.io/research/adminer-4.6.2-file-disclosure-vulnerability");

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

if (version_in_range(version: version, test_version:"1.12.0", test_version2: "4.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
