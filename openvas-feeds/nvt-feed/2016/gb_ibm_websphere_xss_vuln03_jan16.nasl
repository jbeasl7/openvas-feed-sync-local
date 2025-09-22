# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806840");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-01-20 14:48:51 +0530 (Wed, 20 Jan 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2013-4004");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server XSS Vulnerability (swg21644047)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation of input by the
  Administrative Console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to
  inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 8.0.x prior to
  8.0.0.7 and 8.5.x prior to 8.5.5.1.");

  script_tag(name:"solution", value:"Update to version 8.0.0.7, 8.5.5.1 or later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21644047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61935");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
