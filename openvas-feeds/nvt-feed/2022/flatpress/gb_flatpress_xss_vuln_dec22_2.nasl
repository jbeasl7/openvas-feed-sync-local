# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118427");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-12-19 11:00:29 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-13 15:37:00 +0000 (Thu, 13 Oct 2022)");

  script_cve_id("CVE-2022-40047");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Mentioned commit has to be pulled

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FlatPress 1.2.1 XSS Vulnerability (CVE-2022-40047)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to a cross-site scripting (XSS)
  vulnerability via the page parameter at '/flatpress/admin.php'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"FlatPress version 1.2.1.");

  script_tag(name:"solution", value:"The vendor has added a fix into the master repository with
  commit '0a7ad2c'. No new version containing the fix has been released yet.");

  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/153");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/commit/0a7ad2ccb8533b54654907726b48bd7da44e715c");

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

if (version_is_less(version: version, test_version: "1.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See solution", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
