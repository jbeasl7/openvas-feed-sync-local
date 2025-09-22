# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100579");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
  script_cve_id("CVE-2010-1317", "CVE-2010-1318", "CVE-2010-1319");

  script_name("RealNetworks Helix and Helix Mobile Server Multiple RCE Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39490");
  script_xref(name:"URL", value:"http://www.realnetworks.com/products/media_delivery.html");
  script_xref(name:"URL", value:"http://www.realnetworks.com/uploadedFiles/Support/helix-support/SecurityUpdate041410HS.pdf");

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_mandatory_keys("RTSP/server_banner/available");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor released Helix Server and Helix Mobile Server 14.0 to
  address these issues. Please see the references for more information.");

  script_tag(name:"summary", value:"RealNetworks Helix Server and Helix Mobile Server are prone to
  multiple memory-corruption vulnerabilities that can allow attackers to
  execute remote code.

  Exploiting these issues may allow attackers to gain unauthorized
  access to affected computers. Failed attempts may cause crashes and
  deny service to legitimate users of the application.

  These issues affect versions prior to Helix Server and Helix Mobile
  Server 14.0.");
  exit(0);
}

include("version_func.inc");
include("port_service_func.inc");

port = service_get_port(default:554, proto:"rtsp");

if(!server = get_kb_item("RTSP/" + port + "/server_banner"))
  exit(0);

if("Server: Helix" >!< server)
  exit(0);

version = eregmatch(pattern:"Version ([0-9.]+)", string:server);
if(isnull(version[1]))
  exit(0);

if(version_is_less(version:version[1], test_version:"14")) {
  report = report_fixed_ver(installed_version:version[1], fixed_version:"14");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
