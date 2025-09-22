# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rconfig:rconfig";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143091");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-11-05 06:12:25 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-29 19:15:00 +0000 (Tue, 29 Oct 2019)");

  script_cve_id("CVE-2019-16662", "CVE-2019-16663");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("rConfig < 3.9.3 Multiple RCE Vulnerabilities - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rconfig_detect.nasl");
  script_mandatory_keys("rconfig/detected");

  script_tag(name:"summary", value:"rConfig is prone to multiple remote code execution (RCE)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-16663: An authenticated remote code execution vulnerability in lib/crud/search.crud.php

  - CVE-2019-16662: A RCE vulnerability in www/install/lib/ajaxHandlers/ajaxServerSettingsChk.php");

  script_tag(name:"affected", value:"rConfig version 3.9.2 and prior.");

  script_tag(name:"solution", value:"Update rConfig to version 3.9.3 or later.

  Also make sure that the unused www/install/lib/ajaxHandlers/ajaxServerSettingsChk.php file was
  removed from an existing installation.");

  script_xref(name:"URL", value:"https://shells.systems/rconfig-v3-9-2-authenticated-and-unauthenticated-rce-cve-2019-16663-and-cve-2019-16662/");
  script_xref(name:"URL", value:"https://www.rconfig.com/downloads/v3-release-notes");
  script_xref(name:"URL", value:"http://help.rconfig.com/gettingstarted/postinstall");

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

if (version_is_less(version: version, test_version: "3.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
