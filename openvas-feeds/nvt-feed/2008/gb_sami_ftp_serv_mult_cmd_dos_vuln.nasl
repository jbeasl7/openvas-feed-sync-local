# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800305");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5105", "CVE-2008-5106");
  script_name("Sami FTP Server Multiple Commands Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/488198/100/200/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27817");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/samiftp/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to deny the service.");

  script_tag(name:"affected", value:"KarjaSoft Sami FTP Server version 2.0.2 and prior.");

  script_tag(name:"insight", value:"The flaw exists in server, due to improper handling of input passed to the
  commands (e.g., APPE, CWD, DELE, MKD, RMD, RETR, RNFR, RNTO, SIZE, and STOR).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Sami FTP Server is prone to a remote denial of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(! banner || "Sami FTP Server" >!< banner)
  exit(0);

ftpVer = eregmatch(pattern:"Sami FTP Server ([0-9.]+)", string:banner);
if(ftpVer) {
  if(version_is_less_equal(version:ftpVer[1], test_version:"2.0.2")){
    security_message(port);
  }
}
