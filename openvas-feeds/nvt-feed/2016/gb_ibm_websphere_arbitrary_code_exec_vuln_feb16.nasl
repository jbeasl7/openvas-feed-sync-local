# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806874");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-02-19 09:55:23 +0530 (Fri, 19 Feb 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-1920");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Arbitrary Code Execution Vulnerability (Feb 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an arbitrary code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  'Management port'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x through
  6.1.0.47, 7.0.x prior to 7.0.0.39, 8.0.x prior to 8.0.0.11 and 8.5.x prior to 8.5.5.6.");

  script_tag(name:"solution", value:"Update to version 6.1.0.48, 7.0.0.39, 8.0.0.11, 8.5.5.6 or
  later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21883573");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74439");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.48")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.48");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.39");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
