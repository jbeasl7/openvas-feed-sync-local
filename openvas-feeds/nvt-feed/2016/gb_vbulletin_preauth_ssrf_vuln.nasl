# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809158");
  script_version("2025-05-29T05:40:25+0000");
  script_cve_id("CVE-2016-6483");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-08-29 14:43:57 +0530 (Mon, 29 Aug 2016)");
  script_name("vBulletin 3.0.x <= 3.8.9, 4.0.x <= 4.2.3, 5.0.x <= 5.2.2 Preauth SSRF Vulnerability");

  script_tag(name:"summary", value:"vBulletin is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a codebase accepts HTTP redirects from
  the target server specified in a user-provided link.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow unauthenticated remote
  attackers to bypass certain security restrictions to perform unauthorized actions. This may aid in
  further attacks.");

  script_tag(name:"affected", value:"vBulletin versions 5.0 through 5.2.2, 4.0 through 4.2.3 and 3.0
  through 3.8.9.");

  script_tag(name:"solution", value:"Update to version 5.2.3, 4.2.4 Beta, 3.8.10 Beta or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Aug/68");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92350");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

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

if(version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.2.2")) {
  fix = "5.2.3";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.2.3")) {
  fix = "4.2.4 Beta";
  VULN = TRUE;
}

else if(version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.8.9")) {
  fix = "3.8.10 Beta";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
