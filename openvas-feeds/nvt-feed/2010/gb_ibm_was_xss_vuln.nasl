# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only.

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902213");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-0778", "CVE-2010-0779");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server XSS Vulnerability (Jul 2010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Administration Console,
  which allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.0.x prior to
  6.0.2.43, 6.1.x prior to 6.1.0.33 and 7.0.x prior to 7.0.0.11.");

  script_tag(name:"solution", value:"Update to version 6.0.2.43, 6.1.0.33, 7.0.0.11 or later.");

  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=10207");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/395192.php");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59646");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59647");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.2.43")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.2.43");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.33");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.11");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
