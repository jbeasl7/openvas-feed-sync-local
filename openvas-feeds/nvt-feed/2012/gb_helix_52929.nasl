# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103475");
  script_cve_id("CVE-2012-0942", "CVE-2012-1923", "CVE-2012-1984", "CVE-2012-1985", "CVE-2012-2267", "CVE-2012-2268");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("RealNetworks Helix Server Multiple Remote Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52929");
  script_xref(name:"URL", value:"http://helixproducts.real.com/docs/security/SecurityUpdate04022012HS.pdf");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2012-9/");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2012-8/");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-23 14:15:20 +0200 (Mon, 23 Apr 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_mandatory_keys("RTSP/server_banner/available");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"RealNetworks Helix Server is prone to multiple remote vulnerabilities.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary code within
  the context of the affected application, cause denial-of service conditions, retrieve potentially sensitive
  information, execute arbitrary script code in the browser of an unsuspecting user in the context of the
  affected site, and steal cookie-based authentication credentials.");

  script_tag(name:"affected", value:"RealNetworks Helix Server 14.2.0.212 is vulnerable, other versions may
  also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

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

if(version_in_range(version:version[1], test_version:"14", test_version2:"14.2")) {
  report = report_fixed_ver(installed_version:version[1], vulnerable_range:"14 - 14.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
