# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:archiva";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804447");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2014-05-08 17:04:00 +0530 (Thu, 08 May 2014)");

  script_cve_id("CVE-2013-2187");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva < 1.3.8, 2.x < 2.0.1 Home Page XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_http_detect.nasl");
  script_mandatory_keys("apache/archiva/detected");

  script_tag(name:"summary", value:"Apache Archiva is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because the home page does not validate input
  before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in a user's browser within the trust relationship between their browser and
  the server.");

  script_tag(name:"affected", value:"Apache Archiva 1.2 through 1.2.2 and 1.3 before 1.3.8.");

  script_tag(name:"solution", value:"Update to version 1.3.8, 2.0.1 or later.");

  script_xref(name:"URL", value:"http://archiva.apache.org/security.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66998");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Apr/121");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.2", test_version2: "1.2.2") ||
    version_in_range(version: version, test_version: "1.3", test_version2: "1.3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.8/2.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
