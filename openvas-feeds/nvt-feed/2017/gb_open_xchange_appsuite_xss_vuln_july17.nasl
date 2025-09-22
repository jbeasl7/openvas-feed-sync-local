# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810973");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-6846");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-04 15:20:00 +0000 (Tue, 04 Apr 2017)");
  script_tag(name:"creation_date", value:"2017-07-05 11:26:23 +0530 (Wed, 05 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Cross Site Scripting Vulnerability (Jul 2017)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  sanitization of user supplied input while processing requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected application. This may let the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite frontend
  before 7.6.2-rev47, 7.8.0 before 7.8.0-rev30, and 7.8.2 before 7.8.2-rev8.");

  script_tag(name:"solution", value:"Update to version 7.6.2-rev47 or 7.8.0-rev30 or 7.8.2-rev8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93458");
  script_xref(name:"URL", value:"https://software.open-xchange.com/OX6/6.22/doc/Release_Notes_for_Patch_Release_3518_7.6.2_2016-08-29.pdf");
  script_xref(name:"URL", value:"http://software.open-xchange.com/OX6/doc/Release_Notes_for_Patch_Release_3520_7.8.0_2016-08-29.pdf");
  script_xref(name:"URL", value:"https://software.open-xchange.com/OX6/6.22/doc/Release_Notes_for_Patch_Release_3522_7.8.2_2016-08-29.pdf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if(version_is_less(version: version, test_version: "7.6.2.47"))
  fix = "7.6.2-rev47";

else if(version =~ "^7\.8\.0" && version_is_less(version: version, test_version: "7.8.0.30"))
  fix = "7.8.0-rev30";

else if(version =~ "^7\.8\.2" && version_is_less(version: version, test_version: "7.8.2.8"))
  fix = "7.8.2-rev8";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
