# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:edgecore:es3526xa_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808238");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-27 15:50:17 +0530 (Mon, 27 Jun 2016)");
  script_name("EdgeCore ES3526XA Manager Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_edgecore_ES3526XA_manager_remote_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("EdgeCore/ES3526XA/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/62");

  script_tag(name:"summary", value:"EdgeCore ES3526XA Manager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - No CSRF Token is generated per page and / or per (sensitive) function

  - An improper access control mechanism so that any functions can be performed
  by directly calling the function URL (GET/POST) without any authentication

  - It is possible to login with default credential admin:admin or guest:guest,
  and mandatory password change is not enforced by the application");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers silent execution of unauthorized actions on the device such as
  password change, configuration parameter changes, to bypass authentication
  and to perform any administrative functions such as add, update, delete users.");

  script_tag(name:"affected", value:"EdgeCore - Layer2+ Fast Ethernet Standalone Switch ES3526XA Manager.

  Please see the referenced link for the affected switch information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

buf = http_get_cache(item:"/", port:port);
if(!buf || buf !~ "^HTTP/1\.[01] 401")
  exit(0);

foreach credential(make_list("admin:admin", "guest:guest")) {

  userpass = base64(str:credential);
  req = 'GET / HTTP/1.1\r\n' +
        'Authorization: Basic ' + userpass + '\r\n' +
        '\r\n';
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  # nb: No other confirmation is possible
  if(buf =~ "^HTTP/1\.[01] 200" && "cluster_info" >< buf &&
     "cluster_main.htm" >< buf && "cluster_link.htm" >< buf) {
    report = 'It was possible to login using the following credentials:\n\n' + credential;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
