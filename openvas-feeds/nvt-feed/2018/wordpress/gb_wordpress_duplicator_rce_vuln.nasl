# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141688");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-15 11:56:56 +0700 (Thu, 15 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-18 12:03:00 +0000 (Mon, 18 Oct 2021)");

  script_cve_id("CVE-2018-17207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Duplicator Plugin < 1.2.42 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"An issue was discovered in Snap Creek Duplicator. By accessing leftover
installer files (installer.php and installer-backup.php), an attacker can inject PHP code into wp-config.php
during the database setup step, achieving arbitrary code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Snap Creek Duplicator plugin prior to version 1.2.42.");

  script_tag(name:"solution", value:"Update to version 1.2.42 or later and remove the leftover files.");

  script_xref(name:"URL", value:"https://www.synacktiv.com/ressources/advisories/WordPress_Duplicator-1.2.40-RCE.pdf");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

urls = make_list("/installer.php", "/installer-backup.php");

foreach file (urls) {
  url = dir + file;
  res = http_get_cache(port: port, item: url);

  if ("<title>Duplicator</title>" >< res && "<label>Plugin Version:</label>" >< res) {
    vers = eregmatch(pattern: '<td class="dupx-header-version">[^v]+version: ([0-9.]+)', string: res);
    if (!isnull(vers[1])) {
      if (version_is_less(version: vers[1], test_version: "1.2.42")) {
        report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.2.42", file_checked: url);
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
