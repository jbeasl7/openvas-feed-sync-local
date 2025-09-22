# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emc:rsa_archer_grc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106919");
  script_version("2023-12-15T05:06:25+0000");
  script_tag(name:"last_modification", value:"2023-12-15 05:06:25 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-07-03 16:15:11 +0700 (Mon, 03 Jul 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-17 18:06:00 +0000 (Mon, 17 Jul 2017)");

  script_cve_id("CVE-2017-4998", "CVE-2017-4999", "CVE-2017-5000", "CVE-2017-5001", "CVE-2017-5002");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RSA Archer Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rsa_archer_http_detect.nasl");
  script_mandatory_keys("rsa_archer/detected");

  script_tag(name:"summary", value:"RSA Archer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-4998: Cross-site request forgery (CSRF)

  - CVE-2017-4999: Authorization bypass through user-controlled key

  - CVE-2017-5000: Information disclosure

  - CVE-2017-5001: Cross-site scripting (XSS)

  - CVE-2017-5002: Open redirect");

  script_tag(name:"affected", value:"RSA Archer GRC prior to version 6.2.0.2.");

  script_tag(name:"solution", value:"Update to version 6.2.0.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/49");

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

if (version_is_less(version: version, test_version: "6.2.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
