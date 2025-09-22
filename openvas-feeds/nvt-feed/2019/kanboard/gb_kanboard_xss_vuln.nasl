# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kanboard:kanboard";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142492");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-06-05 04:29:48 +0000 (Wed, 05 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-30 04:29:00 +0000 (Thu, 30 May 2019)");

  script_cve_id("CVE-2019-7324");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kanboard < 1.2.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_kanboard_http_detect.nasl");
  script_mandatory_keys("kanboard/detected");

  script_tag(name:"summary", value:"Kanboard is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"app/Core/Paginator.php has an XSS in pagination sorting.");

  script_tag(name:"affected", value:"Kanboard version 1.2.7 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.8 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2019/May/41");
  script_xref(name:"URL", value:"https://www.netsparker.com/web-applications-advisories/ns-19-001-reflected-cross-site-scripting-in-kanboard/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "1.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.8", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
