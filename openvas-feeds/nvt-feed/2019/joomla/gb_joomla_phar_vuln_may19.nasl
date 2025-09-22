# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142473");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-05-31 02:23:57 +0000 (Fri, 31 May 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Joomla! < 3.9.6 Phar Stream Wrapper Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to a protection by-pass vulnerability of the Phar Stream
  Wrapper Interceptor.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Joomla 3.9.3, the vulnerability of insecure deserialization when executing
  Phar archives was addressed by removing the known attack vector in the Joomla core. In order to intercept file
  invocations like file_exists or stat on compromised Phar archives the base name has to be determined and checked
  before allowing to be handled by PHP Phar stream handling. The used implementation however is vulnerable to path
  traversal leading to scenarios where the Phar archive to be assessed is not the actual (compromised) file.");

  script_tag(name:"affected", value:"Joomla! CMS versions 3.9.3 through 3.9.5.");

  script_tag(name:"solution", value:"Update to version 3.9.6 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre.html");

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

if (version_in_range(version: version, test_version: "3.9.3", test_version2: "3.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
