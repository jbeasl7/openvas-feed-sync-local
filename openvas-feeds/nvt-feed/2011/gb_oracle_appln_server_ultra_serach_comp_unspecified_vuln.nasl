# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102113");
  script_version("2024-10-29T05:05:45+0000");
  script_cve_id("CVE-2008-0347");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"creation_date", value:"2011-12-07 12:29:09 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Application Server Ultra Search Component Unspecified Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_mandatory_keys("oracle/application_server/detected");

  script_xref(name:"URL", value:"http://securitytracker.com/id?1019218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27229");
  script_xref(name:"URL", value:"http://www.petefinnigan.com/Advisory_CPU_Jan_2008.htm");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to execute arbitrary code or
  commands in context of the affected application, information disclosure and denial of service.");

  script_tag(name:"affected", value:"Oracle Application server versions 9.0.4.3 and 10.1.2.0.2");

  script_tag(name:"insight", value:"The flaw is due to unspecified error in Oracle ultra search component.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"Oracle application server is prone to an unspecified vulnerability.");

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

if(version_in_range(version:appVer, test_version:"9.0", test_version2:"9.0.4.3") ||
   version_in_range(version:appVer, test_version:"10.1.2.0", test_version2:"10.1.2.0.2")) {
  report = report_fixed_ver(installed_version:appVer, fixed_version:"See references");
  security_message(port:appPort, data:report);
  exit(0);
}

exit(99);
