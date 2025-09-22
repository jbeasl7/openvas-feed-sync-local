# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813163");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2017-18264");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-05-03 12:01:22 +0530 (Thu, 03 May 2018)");
  script_name("phpMyAdmin Security Bypass Vulnerability-PMASA-2017-8");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error where the
  restrictions created for accounts with no password and 'AllowNoPassword' is
  set to false, are bypassed under certain PHP versions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security measures and do login of users who have no password set.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.0 prior to 4.0.10.20,
  4.4.x, 4.6.x, 4.7.0-beta1 and 4.7.0-rc1");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.0.10.20 or
  4.7.0 or newer or apply patch as provided by vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  ##unreliable as Patch, mitigation is also available as solution
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-8");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
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

if(vers == "4.7.0-rc1" || vers == "4.7.0-beta1" || vers =~ "^4.\[46]") {
  fix = "4.7.0";
}

else if(version_in_range(version:vers, test_version:"4.0", test_version2:"4.0.10.19")) {
  fix = "4.0.10.20";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
