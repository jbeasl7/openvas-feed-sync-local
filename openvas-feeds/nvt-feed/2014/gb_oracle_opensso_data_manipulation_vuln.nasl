# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:opensso";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804437");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2012-0079");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-22 14:57:24 +0530 (Tue, 22 Apr 2014)");
  script_name("Oracle OpenSSO Administration Component Data Manipulation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("secpod_sun_opensso_detect.nasl");
  script_mandatory_keys("Oracle/OpenSSO/detected");

  script_tag(name:"summary", value:"Oracle OpenSSO is prone to data manipulation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in the Administration component.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to update, insert, or delete
  certain Oracle OpenSSO accessible data.");

  script_tag(name:"affected", value:"Oracle OpenSSO version 7.1 and 8.0");

  script_tag(name:"solution", value:"Apply the patch.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: The version check below is completely broken...

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2012.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51492");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ooPort = get_app_port(cpe:CPE)){
  exit(0);
}

ooVer = get_app_version(cpe:CPE, port:ooPort);
if(!ooVer){
  exit(0);
}

if(version_is_equal(version:ooVer, test_version:"8.0") ||
   version_is_equal(version:ooVer, test_version:"7.1"))
{
  report = report_fixed_ver(installed_version:ooVer, fixed_version:"Apply the patch");
  security_message(port:ooPort, data:report);
  exit(0);
}
