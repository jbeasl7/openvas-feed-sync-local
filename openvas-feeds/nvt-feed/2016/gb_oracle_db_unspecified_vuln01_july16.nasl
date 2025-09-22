# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808703");
  script_version("2024-10-29T05:05:45+0000");
  script_cve_id("CVE-2016-3479", "CVE-2016-5555", "CVE-2016-5505", "CVE-2016-5498",
                "CVE-2016-5499", "CVE-2016-3562", "CVE-2017-3310", "CVE-2017-3486",
                "CVE-2016-2183", "CVE-2014-3566", "CVE-2017-10261");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-21 18:47:32 +0530 (Thu, 21 Jul 2016)");
  script_name("Oracle Database Server Unspecified Vulnerability -01 (Jul 2016)");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple unspecified errors.

  - Multiple unspecified errors related to components 'DBMS_LDAP',
    'Real Application Clusters' and 'XML Database' components.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated attackers to affect confidentiality, integrity, and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.4 and 12.1.0.2");

  script_tag(name:"solution", value:"Apply the patches from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91898");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93615");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93613");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93620");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70574");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101344");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
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

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"11.2.0.4") ||
   version_is_equal(version:vers, test_version:"12.1.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the appropriate patch", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
