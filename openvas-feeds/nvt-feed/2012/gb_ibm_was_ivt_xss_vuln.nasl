# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802413");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2012-01-18 18:06:52 +0530 (Wed, 18 Jan 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-1362");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server 6.1.x < 6.1.0.41, 7.0.x < 7.0.0.19 IVT XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in Installation Verification Test
  (IVT) application in the Install component, which allows remote attackers to inject arbitrary web
  script or HTML via unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site
  scripting attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x prior to
  6.1.0.41 and 7.0.x prior to 7.0.0.19.");

  script_tag(name:"solution", value:"Update to version 6.1.0.41, 7.0.0.19 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69731");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46736");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM43792");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "6.1", test_version2: "6.1.0.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.41");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version:version, test_version: "7.0", test_version2: "7.0.0.18")){
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.19");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
