# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806824");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-01-19 11:35:34 +0530 (Tue, 19 Jan 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-3306", "CVE-2012-3304", "CVE-2012-3311", "CVE-2012-3325",
                "CVE-2012-4853");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Multiple Vulnerabilities (swg21611313)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper validation of credentials.

  - No CBIND checks when configuring Federated Repositories for IIOP connections and Optimized
  Local Adapters.

  - No purging of password data from the authentication cache, which has unspecified impact and
  remote attack vectors.

  - The some cross site request forgery vulnerability.

  - An error in administrative console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to traverse
  directories on the system, to bypass security restrictions, to hijack a valid user's session and
  leads to information disclosure.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x prior to
  6.1.0.45, 7.0.x prior to 7.0.0.25, 8.0.x prior to 8.0.0.5 and 8.5.x prior to 8.5.0.1.");

  script_tag(name:"solution", value:"Update to version 6.1.0.45, 7.0.0.25, 8.0.0.5, 8.5.0.1 or
  later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21611313");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55678");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56458");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.45")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.45");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.25");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.0.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
