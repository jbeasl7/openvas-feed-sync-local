# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902457");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2011-1355", "CVE-2011-1356");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Multiple Vulnerabilities (Jul 2011)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - 'logoutExitPage' parameter allows to bypass security restrictions

  - Administration Console requests allows local attacker to obtain sensitive information");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users to gain
  sensitive information to redirect users to arbitrary web sites and conduct phishing attacks via
  the logoutExitPage parameter.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x prior to
  6.1.0.39 and 7.x prior to 7.0.0.19.");

  script_tag(name:"solution", value:"Update to version 6.1.0.39, 7.0.0.19 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48710");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68571");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM42436");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.39");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.19");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
