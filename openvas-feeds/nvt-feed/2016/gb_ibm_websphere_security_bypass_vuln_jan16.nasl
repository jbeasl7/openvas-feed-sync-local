# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806844");
  script_version("2024-12-20T05:05:51+0000");
  script_tag(name:"last_modification", value:"2024-12-20 05:05:51 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2016-01-20 17:51:20 +0530 (Wed, 20 Jan 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2013-0462");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Security Bypass Vulnerability (Jan 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to bypass
  certain security restrictions, which may aid in further attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x through
  6.1.0.45, 7.0.x through 7.0.0.27, 8.0.x through 8.0.0.5 and 8.5.x through 8.5.0.1.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-security-vulnerabilites-fixed-ibm-websphere-application-server-8502");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57513");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "6.1", test_version2: "6.1.0.45")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.47");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.0.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.29");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.0.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5", test_version2: "8.5.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
