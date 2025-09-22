# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806847");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-01-20 15:32:25 +0530 (Wed, 20 Jan 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-0544", "CVE-2013-0543", "CVE-2013-0542", "CVE-2013-0541");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Multiple Vulnerabilities (487947)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper validation of user accounts when a Local OS registry is used.

  - An improper validation of input by the Administrative console.

  - The buffer overflow vulnerability when a local OS registry is used in conjunction with
  WebSphere Identity Manager.

  - The directory traversal vulnerability in the Administrative Console");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to modify
  data, to bypass intended access restrictions, to inject arbitrary web script or HTML and to cause
  a denial of service.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x prior to
  6.1.0.47, 7.0.x prior to 7.0.0.29, 8.0.x prior to 8.0.0.6 and 8.5.x prior to 8.5.0.2.");

  script_tag(name:"solution", value:"Update to version 6.1.0.47, 7.0.0.29, 8.0.0.6, 8.5.0.2 or
  later.");

  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-security-vulnerabilites-fixed-ibm-websphere-application-server-8502");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59250");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59249");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59248");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59247");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.47")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.47");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.29");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
