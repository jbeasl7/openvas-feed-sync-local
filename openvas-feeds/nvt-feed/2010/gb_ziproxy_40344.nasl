# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100650");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1513");

  script_name("Ziproxy Image Parsing Multiple Integer Overflow Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40344");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-75/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("secpod_ziproxy_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Ziproxy/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Ziproxy is prone to multiple integer-overflow vulnerabilities because
  it fails to properly validate user-supplied data.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code in
  the context of the application. Failed exploit attempts will likely result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Ziproxy 3.0 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:8080);

if(!vers = get_kb_item(string("www/",port,"/Ziproxy")))exit(0);

if(version_is_less_equal(version: vers, test_version: "3.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less or equal to 3.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
