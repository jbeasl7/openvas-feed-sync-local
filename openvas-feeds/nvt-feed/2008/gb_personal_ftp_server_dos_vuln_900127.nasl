# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900127");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_cve_id("CVE-2008-4136");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Personal FTP Server RETR Command Remote Denial of Service Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://shinnok.evonet.ro/vulns_html/pftp.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31173");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/31173.c");

  script_tag(name:"summary", value:"Personal FTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"This issue is due to an error when handling the RETR command.");

  script_tag(name:"affected", value:"Michael Roth Personal FTP Server 6.0f and prior on Windows (all).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"impact", value:"Successful exploitation will deny the service by sending
  multiple RETR commands with an arbitrary argument.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\The Personal FTP Server_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

pftpVer = registry_get_sz(key:key, item:"DisplayVersion");
if(!pftpVer) exit(0);

if(egrep(pattern:"^([0-5]\..*|6\.0([a-f])?)$", string:pftpVer)){
  report = report_fixed_ver(installed_version:pftpVer, fixed_version:"WillNotFix");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);