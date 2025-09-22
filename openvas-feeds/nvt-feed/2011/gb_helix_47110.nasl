# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103137");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-01 13:32:12 +0200 (Fri, 01 Apr 2011)");
  script_cve_id("CVE-2010-4235", "CVE-2010-4596");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("RealNetworks Helix Server < 14.2 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47110");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47109");
  script_xref(name:"URL", value:"http://docs.real.com/docs/security/SecurityUpdate033111HS.pdf");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_mandatory_keys("RTSP/server_banner/available");

  script_tag(name:"solution", value:"Updates are available. Please see the reference for more details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"RealNetworks Helix Mobile Server and/or Helix Server is prone to a
  remote code-execution and stack-based buffer-overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploits can allow the attacker to execute arbitrary code
  in the context of the application. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"insight", value:"The flaws exist due to:

  - a failure to properly bounds-check user-supplied data.

  - a format-string error.");

  exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:554, proto:"rtsp");

if(!server = get_kb_item("RTSP/" + port + "/server_banner"))
  exit(0);

if("Server: Helix" >!< server)
  exit(0);

version = eregmatch(pattern:"Version ([0-9.]+)", string:server);
if(isnull(version[1]))
  exit(0);

if(version_is_less(version:version[1], test_version:"14.2")) {
  report = report_fixed_ver(installed_version:version[1], fixed_version:"14.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
