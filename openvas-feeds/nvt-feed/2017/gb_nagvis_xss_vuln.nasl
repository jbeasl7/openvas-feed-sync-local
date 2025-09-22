# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagvis:nagvis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106638");
  script_version("2025-06-03T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2017-03-08 12:16:59 +0700 (Wed, 08 Mar 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-07 02:59:00 +0000 (Tue, 07 Mar 2017)");

  script_cve_id("CVE-2017-6393");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NagVis < 1.9b13 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagvis_http_detect.nasl");
  script_mandatory_keys("nagvis/detected");

  script_tag(name:"summary", value:"NagVis is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to insufficient filtration of
  user-supplied data passed to the 'nagvis-master/share/userfiles/gadgets/std_table.php' URL.");

  script_tag(name:"impact", value:"An attacker could execute arbitrary HTML and script code in
  browser in context of the vulnerable website.");

  script_tag(name:"affected", value:"NagVis version 1.8.x, 1.9b12 and prior.");

  script_tag(name:"solution", value:"Apply the provided patch or update to 1.9b13 or later.");

  script_xref(name:"URL", value:"https://github.com/NagVis/nagvis/issues/91");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96537");

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

if (version_in_range(version: version, test_version: "1.8", test_version2: "1.8.5") ||
    version_in_range(version: version, test_version: "1.9b1", test_version2: "1.9b12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9b13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
