# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812813");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2018-7260");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-06 15:07:00 +0000 (Tue, 06 Mar 2018)");
  script_tag(name:"creation_date", value:"2018-02-28 12:56:43 +0530 (Wed, 28 Feb 2018)");
  script_name("phpMyAdmin XSS Vulnerability (PMASA-2018-1) - Linux");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an invalidated
  variable total_rows of db_central_columns.php page.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to inject arbitrary web script or HTML via a crafted URL.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.7.x prior to 4.7.8.");

  script_tag(name:"solution", value:"Upgrade to version 4.7.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103099");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_unixoide", "phpMyAdmin/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^4\.7" && version_is_less(version:vers, test_version:"4.7.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.7.8", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
