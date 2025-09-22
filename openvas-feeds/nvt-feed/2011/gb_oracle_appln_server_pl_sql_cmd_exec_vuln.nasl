# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102112");
  script_version("2024-10-29T05:05:45+0000");
  script_cve_id("CVE-2006-0435");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"creation_date", value:"2011-12-07 12:32:19 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Application Server Multiple Unspecified Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_mandatory_keys("oracle/application_server/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/169164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16384");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1015961");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/24363");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/423822/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/423819/100/0/threaded");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2006-090826.html");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to send a specially-crafted HTTP
  request to bypass the PLSQLExclusion list and execute SQL commands on the back-end database with DBA privileges.");

  script_tag(name:"affected", value:"Oracle Application server versions 1.0.2.2, 9.0.4.2, 10.1.2.0.2, 10.1.2.1 and 10.1.3.0.0");

  script_tag(name:"insight", value:"The flaw is due to error in Oracle PL/SQL Gateway, which fails to
  properly validate user-supplied HTTP requests.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"Oracle application server is prone to SQL command execution vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:oracle:application_server";

if(!appPort = get_app_port(cpe:CPE))
  exit(0);

if(!appVer = get_app_version(cpe:CPE, port:appPort))
  exit(0);

if(version_is_less(version:appVer, test_version:"1.0.2.2") ||
   version_in_range(version:appVer, test_version:"9.0", test_version2:"9.0.4.2") ||
   version_in_range(version:appVer, test_version:"10.1.2.0", test_version2:"10.1.3.0")) {
  report = report_fixed_ver(installed_version:appVer, fixed_version:"See references");
  security_message(port:appPort, data:report);
  exit(0);
}

exit(99);
