# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143055");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2019-10-25 04:13:50 +0000 (Fri, 25 Oct 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-10 20:29:00 +0000 (Thu, 10 Oct 2019)");

  script_cve_id("CVE-2019-17130");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("vBulletin < 5.5.5 URL Mishandling Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"summary", value:"vBulletin mishandles external URLs within the /core/vb/vurl.php
  file and the /core/vb/vurl directories.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"vBulletin 5.5.4 and prior.");

  script_tag(name:"solution", value:"Update to 5.5.5 or later. Additional make sure the
  /core/vb/vurl.php file and /core/vb/vurl directories are deleted from your server.");

  script_xref(name:"URL", value:"https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4423391-vbulletin-5-5-5-alpha-4-available-for-download");

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

if (version_is_less(version: version, test_version: "5.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
