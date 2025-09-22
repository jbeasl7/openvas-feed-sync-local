# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_mq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808652");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2015-2012");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 02:59:00 +0000 (Tue, 06 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-08-16 12:32:21 +0530 (Tue, 16 Aug 2016)");

  script_name("IBM WebSphere MQ 'MQXR Service' Information Disclosure Vulnerability (swg21968399)");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the passphrase used to access
  the keystore is written to the file system in clear text in a properties file that
  is world readable.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users
  to obtain sensitive information.");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 7.1 before 7.1.0.7,
  7.5 through 7.5.0.5, and 8.0 before 8.0.0.4.");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 7.1.0.7,
  or 7.5.0.6, or 8.0.0.4, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21968399");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82992");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

if (version_in_range(version:version, test_version:"8.0", test_version2:"8.0.0.3")) {
  fix = "8.0.0.4";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"7.5", test_version2:"7.5.0.5")) {
  fix = "7.5.0.6";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"7.1", test_version2:"7.1.0.6")) {
  fix = "7.1.0.7";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
