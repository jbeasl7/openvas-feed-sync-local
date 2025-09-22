# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142795");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-08-27 02:46:05 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-28 19:05:00 +0000 (Wed, 28 Aug 2019)");

  script_cve_id("CVE-2019-15314");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Tiki Wiki CMS Groupware <= 18.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"tiki/tiki-upload_file.php allows remote attackers to upload
  JavaScript code that is executed upon visiting a tiki/tiki-download_file.php?display&fileId=
  URI.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 18.4 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://pastebin.com/wEM7rnG7");

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

if (version_is_less_equal(version: version, test_version: "18.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
