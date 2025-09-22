# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812374");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2017-1000499");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-30 18:36:00 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-01-03 12:48:13 +0530 (Wed, 03 Jan 2018)");
  script_name("phpMyAdmin XSRF/CSRF Vulnerability (PMASA-2017-9) - Linux");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as certain requests were
  not protected against CSRF attack.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to perform harmful database operations such as
  deleting records, dropping/truncating tables, etc.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.7.x prior to 4.7.7");

  script_tag(name:"solution", value:"Update to version 4.7.7 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-9/");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^4\.7\." && (version_is_less(version:vers, test_version:"4.7.7"))) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.7.7", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
