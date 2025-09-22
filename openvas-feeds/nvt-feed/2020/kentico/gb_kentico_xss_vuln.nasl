# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kentico:kentico";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143408");
  script_version("2025-03-25T05:38:56+0000");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:56 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"creation_date", value:"2020-01-28 02:59:59 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-20 06:37:00 +0000 (Sun, 20 Feb 2022)");

  script_cve_id("CVE-2019-19493");

  # nb: Only major version extracted in newer versions
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kentico CMS < 12.0.50 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kentico_cms_http_detect.nasl");
  script_mandatory_keys("kentico/cms/detected");

  script_tag(name:"summary", value:"Kentico CMS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Kentico CMS allows file uploads in which the Content-Type
  header is inconsistent with the file extension, leading to XSS.");

  script_tag(name:"affected", value:"Kentico CMS prior to version 12.0.50.");

  script_tag(name:"solution", value:"Update to version 12.0.50 or later.");

  script_xref(name:"URL", value:"https://devnet.kentico.com/download/hotfixes#securityBugs-v12");

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

if (version_is_less(version: version, test_version: "12.0.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.50", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
