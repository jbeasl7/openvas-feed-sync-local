# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809349");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-10-13 14:40:54 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:30:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-5983");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Code Execution Vulnerability (Oct 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere_or_liberty/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation of a serialized
  object from untrusted sources.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote authenticated users
  to execute arbitrary Java code.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 7.0.x prior 7.0.0.43,
  8.0.x prior 8.0.0.13, 8.5.x prior to 8.5.5.11, 9.0.x prior to 9.0.0.2 and Liberty prior to
  16.0.0.4.");

  script_tag(name:"solution", value:"Update to version to 7.0.0.43, 8.0.0.13, 8.5.5.11, 9.0.0.2
  (IBM WebSphere Application Server) or 16.0.0.4 (WebSphere Liberty) or later.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21990060");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93162");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (get_kb_item("ibm/websphere/liberty/detected")) {
  if (version_is_less(version: version, test_version: "16.0.0.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.0.0.4");
    security_message(port: 0, data: report);
    exit(0);
  }
} else {
  if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.43")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.43");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.13");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.11");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.0.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.0.0.2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
