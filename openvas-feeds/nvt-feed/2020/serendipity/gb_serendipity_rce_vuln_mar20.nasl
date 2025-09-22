# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143659");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-03-31 02:18:43 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-27 19:23:00 +0000 (Fri, 27 Mar 2020)");

  script_cve_id("CVE-2020-10964");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Serendipity < 2.3.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Serendipity/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Serendipity on Windows is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Serendipity on Windows allows remote attackers to execute arbitrary code
  because the filename of a renamed file may end with a dot. This file may then be renamed to have a .php filename.");

  script_tag(name:"affected", value:"Serendipity versions before 2.3.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.3.4 or later.");

  script_xref(name:"URL", value:"https://blog.s9y.org/archives/290-Serendipity-2.3.4-released-security-update.html");
  script_xref(name:"URL", value:"https://github.com/s9y/Serendipity/releases/tag/2.3.4");

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

if (version_is_less(version: version, test_version: "2.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.4", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
