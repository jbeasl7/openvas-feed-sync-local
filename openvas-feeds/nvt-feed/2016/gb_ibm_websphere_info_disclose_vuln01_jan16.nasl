# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806832");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-01-19 16:11:16 +0530 (Tue, 19 Jan 2016)");

  script_cve_id("CVE-2013-6330");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Information Disclosure Vulnerability (swg21661323)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw occurs if the WebSphere Application Server is
  configured to use static file caching using the simpleFileServlet.");

  script_tag(name:"impact", value:"Successful exploitation may allow a remote attacker to obtain
  sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 7.x prior to
  7.0.0.31.");

  script_tag(name:"solution",value:"Update to version 7.0.0.31 or later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21661323");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65100");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.0.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.31");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
