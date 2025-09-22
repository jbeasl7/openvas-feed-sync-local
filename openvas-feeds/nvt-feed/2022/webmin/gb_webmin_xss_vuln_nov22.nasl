# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126206");
  script_version("2023-11-10T16:09:31+0000");
  script_tag(name:"last_modification", value:"2023-11-10 16:09:31 +0000 (Fri, 10 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-11-10 09:23:33 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-04 01:29:00 +0000 (Fri, 04 Nov 2022)");

  script_cve_id("CVE-2022-3844");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Webmin < 2.003 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("usermin_or_webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An XSS vulnerability exists in an unknown function of the file
  xterm/index.cgi.");

  script_tag(name:"affected", value:"Webmin prior to version 2.003.");

  script_tag(name:"solution", value:"Update to version 2.003 or later.

  Note: While there is no dedicated mention of the fix in any changelog the relevant code fix/commit
  as been included in the GitHub tag '2.003'.");

  script_xref(name:"URL", value:"https://github.com/webmin/webmin/compare/2.001...2.003");
  script_xref(name:"URL", value:"https://github.com/webmin/webmin/commit/d3d33af3c0c3fd3a889c84e287a038b7a457d811");

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

if (version_is_less(version: version, test_version: "2.003")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.003", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
