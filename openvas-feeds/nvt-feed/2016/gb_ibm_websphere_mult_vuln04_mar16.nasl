# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807621");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-03-21 14:49:58 +0530 (Mon, 21 Mar 2016)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2015-1882", "CVE-2015-0175", "CVE-2015-0174");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Liberty Profile Multiple Vulnerabilities (swg21697368)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/liberty/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server Liberty Profile is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The Run-as user for EJB not being honored under multi-threaded race conditions.

  - An error with the authData elements.

  - An improper handling of configuration data in SNMP implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  elevated privileges on the system, also to obtain sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server Liberty Profile version 8.5.x
  prior to 8.5.5.5.");

  script_tag(name:"solution", value:"Update to version 8.5.5.5 or later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21697368");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74222");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74223");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74215");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
