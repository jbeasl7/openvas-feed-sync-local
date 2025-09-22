# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801647");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-0784", "CVE-2010-4220");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server 7.x < 7.0.0.13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-site scripting (XSS) in the administrative console due to improper filtering on input
  values

  - Cross-site scripting (XSS) in the Integrated Solution Console due to improper filtering on
  input values");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site
  scripting attacks and cause a Denial of Service (DoS).");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 7.0 prior to
  7.0.0.13.");

  script_tag(name:"solution", value:"Update to version 7.0.0.13 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44875");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2595");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
