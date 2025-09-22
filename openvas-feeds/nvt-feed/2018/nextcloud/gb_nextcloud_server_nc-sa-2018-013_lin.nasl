# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112416");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-11-01 11:49:50 +0100 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16463");

  script_name("Nextcloud Server < 14.0.0, < 13.0.3, < 12.0.8 Session fixation on public share page (NC-SA-2018-013) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"A bug causing session fixation could potentially
  allow an attacker to obtain access to password protected shares.");

  script_tag(name:"affected", value:"Nextcloud Server before version 14.0.0, 13.0.x
  before 13.0.3 and 12.0.x before 12.0.8.");

  script_tag(name:"solution", value:"Upgrade Nextcloud Server to version 12.0.8, 13.0.3,
  or 14.0.0 respectively.");

  script_xref(name:"URL", value:"https://hackerone.com/reports/237184");
  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2018-013");

  exit(0);
}

CPE = "cpe:/a:nextcloud:nextcloud_server";

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.0.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.0.8", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"13.0.0", test_version2:"13.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"13.0.3", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
