# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:visualware:myconnection_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126744");
  script_version("2024-05-15T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-05-15 05:05:27 +0000 (Wed, 15 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-11 18:42:17 +0000 (Sat, 11 May 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-42032", "CVE-2023-42033", "CVE-2023-42034", "CVE-2023-42035");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyConnection Server 11.3c < 11.3d Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_myconnection_server_http_detect.nasl");
  script_mandatory_keys("visualware/myconnection/server/detected");

  script_tag(name:"summary", value:"MyConnection Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-42032: MyConnection Server allows to information disclosure within the
  doRTAAccessUPass, an exposed dangerous method. Attacker can leverage this vulnerability to
  disclose information in the context of the application.

  - CVE-2023-42033: Due to the improper restriction of XML External Entity (XXE) references, a
  crafted document specifying an URI causes the XML parser to access the URI and embed the contents
  back into the XML document for further processing. An attacker can use this vulnerability to
  disclose information in the context of root.

  - CVE-2023-42034: MyConnection Server allows to authentication bypass within the
  doRTAAccessCTConfig method. The issue results from the lack of proper validation of user-supplied
  data, which can lead to the injection of an arbitrary script. An attacker can leverage this
  vulnerability to bypass authentication on the system.

  - CVE-2023-42035: MyConnection Server allows to remote code execution (RCE) within the
  doPostUploadfiles method. The issue results from the lack of proper validation of a user-supplied
  path prior to using it in file operations. An attacker can leverage this vulnerability to execute
  code in the context of root.");

  script_tag(name:"affected", value:"MyConnection Server version 11.3c prior to 11.3d");

  script_tag(name:"solution", value:"Update to version 11.3d or later.");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1398/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1397/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1399/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1396/");
  script_xref(name:"URL", value:"https://myconnectionserver.visualware.com/support/security-advisories");

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

if (version_is_equal(version: version, test_version: "11.3c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.3d", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
