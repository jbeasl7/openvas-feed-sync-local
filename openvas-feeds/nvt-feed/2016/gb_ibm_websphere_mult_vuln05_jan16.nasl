# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806829");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-01-19 13:56:59 +0530 (Tue, 19 Jan 2016)");

  script_cve_id("CVE-2013-6323", "CVE-2014-0859");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Multiple Vulnerabilities (swg21669554)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - insufficient validation of user supplied input by Administration Console.

  - An error in web server plugin when is configured to retry failed POST requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML and also to cause a denial of service (daemon crash).");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 7.x prior to
  7.0.0.33, 8.x prior to 8.0.0.9 and 8.5.x prior to 8.5.5.2.");

  script_tag(name:"solution", value:"Update to version 7.0.0.33, 8.0.0.9, 8.5.5.2 or later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21669554");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67720");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67335");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.33");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.9");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
