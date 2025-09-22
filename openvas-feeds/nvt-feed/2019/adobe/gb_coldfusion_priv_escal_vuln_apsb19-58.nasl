# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815684");
  script_version("2025-01-15T05:38:11+0000");
  script_cve_id("CVE-2019-8256");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:21:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2019-12-12 10:56:11 +0530 (Thu, 12 Dec 2019)");
  script_name("Adobe ColdFusion Privilege Escalation Vulnerability (APSB19-58)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insecure inherited
  permissions of default installation directory.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  gain elevated privileges.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 2018 Update 6 and earlier.");

  script_tag(name:"solution", value:"Update to version 2018 Update 7 or later.");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-58.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/coldfusion/kb/coldfusion-2018-update-7.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/coldfusion/kb/coldfusion-2018-updates.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_coldfusion_http_detect.nasl");
  script_mandatory_keys("adobe/coldfusion/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+")) # nb: The HTTP Detection VT might only extract the major version like 11 or 2021
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^2018\.0" && version_is_less(version: version, test_version: "2018.0.07.316715")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2018 Update 7", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
