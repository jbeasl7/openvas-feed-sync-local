# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106682");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-03-22 16:06:50 +0700 (Wed, 22 Mar 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-29 01:29:00 +0000 (Sun, 29 Oct 2017)");

  script_cve_id("CVE-2017-7203");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder <= 1.30.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_http_detect.nasl");
  script_mandatory_keys("zoneminder/detected");

  script_tag(name:"summary", value:"ZoneMinder is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists due to insufficient filtration of
  user-supplied data in 'postLoginQuery' HTTP POST parameter passed to
  'ZoneMinder-master/web/skins/classic/views/js/postlogin.js.php' URL.");

  script_tag(name:"impact", value:"An attacker could execute arbitrary HTML and script code in
  browser in context of the vulnerable website.");

  script_tag(name:"affected", value:"ZoneMinder version 1.30.1 and prior.");

  script_tag(name:"solution", value:"Apply the provided patch.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/issues/1797");

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

if (version_is_less_equal(version: version, test_version: "1.30.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
