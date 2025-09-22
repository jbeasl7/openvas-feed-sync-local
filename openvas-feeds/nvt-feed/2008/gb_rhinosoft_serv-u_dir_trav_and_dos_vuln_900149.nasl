# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900149");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-14 16:57:31 +0200 (Tue, 14 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Serv-U File Renaming Directory Traversal and 'STOU' DoS Vulnerabilities");
  script_dependencies("secpod_servu_ftp_server_detect.nasl");
  script_mandatory_keys("Serv-U/FTPServ/Ver");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6660");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31563");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32150/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45653");

  script_tag(name:"summary", value:"Serv-U FTP Server is prone to directory traversal and denial of
  service (DoS) vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to:

  - error in handling 'STOU' FTP command. It can exhaust available CPU resources when exploited
  through a specially crafted argument value.

  - input validation error in the FTP service when renaming files which can be exploited to
  overwrite or rename files via directory traversal attacks.");

  script_tag(name:"affected", value:"RhinoSoft Serv-U FTP Server 7.3.0.0 and prior.");

  script_tag(name:"solution", value:"Update to version 10 or later.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to write arbitrary
  files to locations outside of the application's current directory, and deny the service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Serv-U/FTPServ/Ver"))
  exit(0);

if(egrep(pattern:"^(7\.3(\.0(\.0)?)?)$", string:vers)) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
