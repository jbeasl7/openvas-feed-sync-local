# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811695");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-09-14 13:42:29 +0530 (Thu, 14 Sep 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-15 17:45:00 +0000 (Fri, 15 Sep 2017)");

  script_cve_id("CVE-2017-1519");

  script_name("IBM Db2 Denial of Service Vulnerability (Sep 2017)");

  script_tag(name:"summary", value:"IBM Db2 is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in implementation of DB2 connect server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote user to cause disruption of service
  for Db2 Connect Server setup with a particular configuration.");

  script_tag(name:"affected", value:"IBM Db2 versions 10.5 before 10.5 FP8 and 11.1.2.2 before 11.1.2.2 FP2.");

  script_tag(name:"solution", value:"Apply the appropriate fix from reference link");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22007183");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100688");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.0.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "11.1.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.1.2.2 FP2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
