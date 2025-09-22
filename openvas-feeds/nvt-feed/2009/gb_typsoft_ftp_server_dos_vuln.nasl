# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801058");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4105");
  script_name("TYPSoft FTP Server 'APPE' and 'DELE' Commands DOS Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54407");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37114");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Nov/1023234.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_typsoft_ftp_detect.nasl");
  script_mandatory_keys("TYPSoft/FTP/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the user crash the application to
  cause denial of service.");

  script_tag(name:"affected", value:"TYPSoft FTP Server version 1.10 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling the 'APPE' and 'DELE'
  commands. These can be exploited through sending multiple login requests over the same socket.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to version 1.11 or later.");

  script_tag(name:"summary", value:"TYPSoft FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_xref(name:"URL", value:"http://www.softpedia.com/get/Internet/Servers/FTP-Servers/TYPSoft-FTP-Server.shtml");

  exit(0);
}

include("version_func.inc");


tsftpVer = get_kb_item("TYPSoft/FTP/Ver");
if(tsftpVer != NULL)
{
  if(version_is_less_equal(version:tsftpVer, test_version:"1.10")){
    report = report_fixed_ver(installed_version:tsftpVer, vulnerable_range:"Less than or equal to 1.10");
    security_message(port: 0, data: report);
  }
}
