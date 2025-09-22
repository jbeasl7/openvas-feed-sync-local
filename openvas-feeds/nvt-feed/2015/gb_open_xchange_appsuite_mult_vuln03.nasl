# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806522");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-5200", "CVE-2013-5935", "CVE-2013-5936", "CVE-2013-5934");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-11-02 10:34:36 +0530 (Mon, 02 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Multiple Vulnerabilities -03 (Nov 2015)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to error in
  the Hazelcast based cluster API implementation at the Open-Xchange backend.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass access restriction and to obtain sensitive information.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions
  7.0.x before 7.0.2-rev15 and 7.2.x before 7.2.2-rev16");

  script_tag(name:"solution", value:"Update to version 7.0.2-rev15 or 7.2.2-rev16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2013-09/0032.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62311");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.2.14"))
  fix = "7.0.2-rev15";

else if (version_in_range(version: version, test_version: "7.2", test_version2: "7.2.2.15"))
  fix = "7.2.2-rev16";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
