# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117252");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2021-03-17 08:48:37 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2014-5459");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP <= 5.6.0 'PEAR' Symlink Attack Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a symlink attack vulnerability in the included
  PEAR installer.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The PEAR_REST class in REST.php in PEAR allows local users to
  write to arbitrary files via a symlink attack on a (1) rest.cachefile or (2) rest.cacheid file in
  /tmp/pear/cache/, related to the retrieveCacheFirst and useLocalCache functions.");

  script_tag(name:"affected", value:"PHP through version 5.6.0.");

  script_tag(name:"solution", value:"Update to a later PHP version including an PEAR installer in
  version 1.9.2 or later.");

  script_xref(name:"URL", value:"https://pear.php.net/bugs/bug.php?id=18056");
  script_xref(name:"URL", value:"https://pear.php.net/bugs/bug.php?id=18055");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/08/27/3");

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

if (version_is_less_equal(version: version, test_version: "5.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
