# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813449");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-12613");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-02 17:59:00 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2018-06-26 11:47:09 +0530 (Tue, 26 Jun 2018)");
  script_name("phpMyAdmin File Inclusion Vulnerability (PMASA-2018-4) - Windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error from a portion
  of code where pages are redirected and loaded within phpMyAdmin and an improper
  test for whitelisted pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to view and potentially execute files on the server.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.8.0 and 4.8.1 on windows");

  script_tag(name:"solution", value:"Upgrade to version 4.8.2 or newer. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44928");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104532");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-4");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "4.8.0" || vers == "4.8.1") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.2", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
