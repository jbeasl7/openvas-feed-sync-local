# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112011");
  script_version("2024-02-13T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-08-21 10:07:21 +0200 (Mon, 21 Aug 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2014-4349");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin Multiple XSS Vulnerabilities (PMASA-2014-3) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple XSS vulnerabilities allow remote authenticated users to
  inject arbitrary web script or HTML via a crafted table name that is improperly handled after a
  (1) hide or (2) unhide action.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.1.x prior to 4.1.14.1 and 4.2.x prior to
  4.2.4.");

  script_tag(name:"solution", value:"Update to version 4.1.14.1, 4.2.4 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2014-3/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68205");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^4\.1\.") {
  if (version_is_less(version: version, test_version: "4.1.14.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.1.14.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^4\.2\.") {
  if (version_is_less(version: version, test_version: "4.2.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
