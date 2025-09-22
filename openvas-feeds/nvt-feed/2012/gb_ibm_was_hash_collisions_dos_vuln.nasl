# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802418");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2012-01-23 14:06:41 +0530 (Mon, 23 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2012-0193");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Hash Collisions DoS Vulnerability (Jan 2012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a denial of
  service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in computing hash values for 'form'
  parameters without restricting the ability to trigger hash collisions predictably which allows
  remote attackers to cause a denial of service.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of
  service (CPU consumption) by sending many crafted parameters.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.0.x through
  6.0.2.43, 6.1.x prior to 6.1.0.43, 7.0.x prior to 7.0.0.23 and 8.0.x prior to 8.0.0.3.");

  script_tag(name:"solution", value:"Update to version 6.1.0.43, 7.0.0.23, 8.0.0.3 or later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24031821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51441");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21577532");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM53930");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "6.0", test_version2: "6.0.2.43") ||
    version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.43");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.23");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
