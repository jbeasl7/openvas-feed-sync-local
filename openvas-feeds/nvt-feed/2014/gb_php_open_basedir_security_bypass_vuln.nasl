# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804241");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2014-02-19 16:40:59 +0530 (Wed, 19 Feb 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-1171");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("PHP 'open_basedir' Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in libxml RSHUTDOWN function allows remote
  attackers to bypass open_basedir protection mechanism through stream_close method call.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  arbitrary files.");

  script_tag(name:"affected", value:"PHP versions 5.x through 5.0.5, 5.1.x through 5.1.6, 5.2.x
  through 5.2.17, 5.3.x through 5.3.27, 5.4.x through 5.4.23 and 5.5.x through 5.5.6.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=802591");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.5") ||
    version_in_range(version: version, test_version: "5.1.0", test_version2: "5.1.6") ||
    version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.17") ||
    version_in_range(version: version, test_version: "5.3.0", test_version2: "5.3.27") ||
    version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.23") ||
    version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
