# SPDX-FileCopyrightText: 2003 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11202");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("Enhydra Multiserver Default Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("Enhydra/banner");
  script_require_ports("Services/www", 8001);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Please set a strong password of the 'admin' account.");

  script_tag(name:"summary", value:"This system appears to be running the Enhydra application
  server configured with the default administrator password of 'enhydra'.");

  script_tag(name:"impact", value:"An attacker could reconfigure this service and use
  it to obtain full access to the system.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:8001);
banner = http_get_remote_headers(port:port);
if(! banner || "Enhydra" >!< banner)
  exit(0);

url = "/Admin.po?proceed=yes";
req = http_get_req(port:port, url:url, add_headers:make_array("Authorization", "Basic YWRtaW46ZW5oeWRyYQ=="));
res = http_keepalive_send_recv(data:req, port:port);
if(!res)
  exit(0);

if("Enhydra Multiserver Administration" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
