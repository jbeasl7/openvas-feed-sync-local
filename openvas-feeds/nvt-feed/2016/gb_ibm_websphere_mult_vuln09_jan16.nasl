# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806837");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-01-20 10:55:16 +0530 (Wed, 20 Jan 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-5414", "CVE-2013-5417", "CVE-2013-5418");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Multiple Vulnerabilities (498041)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The migration functionality does not properly support the distinction between the admin role
  and the adminsecmanager role

  - An improper validation of HTTP response data.

  - An improper validation of input in the Administrative console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to inject
  arbitrary web script or HTML and to gain privileges on the system.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 7.0.x prior to
  7.0.0.31, 8.0.x prior to 8.0.0.8 and 8.5.x prior to 8.5.5.1.");

  script_tag(name:"solution", value:"Update to version 7.0.0.31, 8.0.0.8, 8.5.5.1 or later.");

  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-potential-security-vulnerabilities-fixed-ibm-websphere-application-server-8551");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63781");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63780");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63778");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.31");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
