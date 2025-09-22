# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807034");
  script_version("2024-10-29T05:05:45+0000");
  script_cve_id("CVE-2016-0472", "CVE-2016-0467", "CVE-2016-0461", "CVE-2016-0499",
                "CVE-2015-4923", "CVE-2015-4921", "CVE-2015-4900", "CVE-2015-4888",
                "CVE-2015-4873", "CVE-2015-4863", "CVE-2015-4796", "CVE-2015-4794",
                "CVE-2016-0690", "CVE-2016-0681", "CVE-2016-0691", "CVE-2016-3454",
                "CVE-2016-3609", "CVE-2016-3506", "CVE-2016-3489", "CVE-2016-3484");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-01-22 13:02:26 +0530 (Fri, 22 Jan 2016)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities -01 (Jan 2016)");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.4, 12.1.0.1, and 12.1.0.2");

  script_tag(name:"solution", value:"Apply the patchesfrom the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77177");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77197");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77183");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77175");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77189");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91874");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91842");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_oracle_database_consolidation.nasl");
  script_mandatory_keys("oracle/database/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if(ver =~ "^(12\.1|11\.2)") {
  if(version_is_equal(version:ver, test_version:"11.2.0.4") ||
     version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"12.1.0.2")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"Apply the appropriate patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
