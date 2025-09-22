# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813158");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2018-10188");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-21 16:39:00 +0000 (Mon, 21 May 2018)");
  script_tag(name:"creation_date", value:"2018-05-02 17:13:20 +0530 (Wed, 02 May 2018)");
  script_name("phpMyAdmin Cross-Site Request Forgery Vulnerability-PMASA-2018-2");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to failure in the
  '/sql.php' script to properly verify the source of HTTP request.");

  script_tag(name:"impact", value:"Successful exploitation of this cross-site
  request forgery (CSRF) allows an attacker to execute arbitrary SQL statement
  by sending a malicious request to a logged in user.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.8.0");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.8.0-1 or
  newer version or apply patch from vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  ##unreliable as Patch is also available as solution
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-2/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103936");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44496/");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
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

if(vers == "4.8.0") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.0-1", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
