# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_mq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805577");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2015-0189");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-05-29 12:42:21 +0530 (Fri, 29 May 2015)");

  script_name("IBM WebSphere MQ DoS Vulnerability (May 2015)");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error
  in the repository manager.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to overwrite memory and cause a denial of service condition.");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 7.5 before 7.5.0.5
  and 8.0 before 8.0.0.2.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 7.5.0.5 or 8.0.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21883457");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74706");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_in_range(version:version, test_version:"7.5", test_version2:"7.5.0.4")) {
  fix = "7.5.0.5";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"8.0", test_version2:"8.0.0.1")) {
  fix = "8.0.0.2";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
