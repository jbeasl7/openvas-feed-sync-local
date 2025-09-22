# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103721");
  script_cve_id("CVE-2013-2567", "CVE-2013-2569", "CVE-2013-2568", "CVE-2013-2570");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-27T05:05:08+0000");

  script_name("Zavio IP Cameras Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60189");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60191");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60190");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60188");
  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/zavio-IP-cameras-multiple-vulnerabilities");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-01 18:57:00 +0000 (Sat, 01 Feb 2020)");
  script_tag(name:"creation_date", value:"2013-05-29 16:28:20 +0200 (Wed, 29 May 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Boa/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Update firmware.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Zavio IP Cameras are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  1. [CVE-2013-2567] to bypass user web interface authentication using hard-coded credentials.

  2. [CVE-2013-2568] to execute arbitrary commands from the administration web  interface. This
  flaw can also be used to obtain all credentials of registered users.

  3. [CVE-2013-2569] to access the camera video stream.

  4. [CVE-2013-2570] to execute arbitrary commands from the administration web
  interface (post authentication only).");

  script_tag(name:"affected", value:"Zavio IP Cameras running firmware version 1.6.03 and below are
  vulnerable.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Boa/" >!< banner)
  exit(0);

user = "manufacture";
pass = "erutcafunam";

userpass = string(user, ":", pass);
userpass64 = base64(str:userpass);

url = "/cgi-bin/mft/wireless_mft"; # i see a lot of devices dying when trying to run a command. So just check for the auth bypass

host = http_host_name(port:port);

req = string("GET ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n\r\n");
resp = http_send_recv(port:port, data:req);
if(! resp || resp !~ "^HTTP/1\.[01] 401")
  exit(0);

req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Authorization: Basic ", userpass64, "\r\n",
             "\r\n");
resp = http_send_recv(port:port, data:req);

if(resp =~ "^HTTP/1\.[01] 200") {
  security_message(port:port);
  exit(0);
}

exit(99);
