# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:soliddb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801937");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-1208");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("IBM solidDB RPC Test Commands Denial of Service Vulnerabilities");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025451");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47584");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67019");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1117");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-142/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_mandatory_keys("IBM-soliddb/installed");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers to crash
  an affected process or consume CPU resources, creating a denial of service
  condition.");
  script_tag(name:"affected", value:"IBM solidDB 4.5.x before 4.5.182, 6.0.x before 6.0.1069, 6.1.x,
  6.3.x before 6.3 FP8, and 6.5.x before 6.5 FP4");
  script_tag(name:"insight", value:"The flaws are caused by a NULL pointer error in the solidDB component when
  processing the 'rpc_test_svc_readwrite' and 'rpc_test_svc_done commands'
  commands sent to port 2315/TCP.");
  script_tag(name:"solution", value:"Apply the patches from the referenced advisory.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"IBM solidDB is prone to multiple denial of service vulnerabilities.");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21496106");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

version = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9.]+)", string: ver);
if(version[1] != NULL)
  ver = version[1];

if(version_is_less(version:ver, test_version:"4.5.182")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"4.5.182");
  security_message(port: port, data: report);
  exit(0);
}

if(ver =~ "^6\.0\.*") {
  if(version_is_less(version:ver, test_version:"6.0.1069")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"6.0.1069");
    security_message(port: port, data: report);
    exit(0);
  }
}

if(ver =~ "^6\.1\.*") {
  security_message(port:port);
  exit(0);
}

if(ver =~ "^06\.3.*") {
  if(version_is_less(version:ver, test_version:"06.30.0049")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"06.30.0049");
    security_message(port: port, data: report);
    exit(0);
  }
}

if(ver =~ "^6\.5\.*") {
  if(version_is_less(version:ver, test_version:"6.5.0.4")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"6.5.0.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
