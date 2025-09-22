# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:httpfilesever:hfs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806814");
  script_version("2024-02-20T05:05:48+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-6287");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 21:56:00 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2016-01-11 15:22:37 +0530 (Mon, 11 Jan 2016)");
  script_name("HTTP File Server Remote Command Execution Vulnerability-02 (Jan 2016)");

  script_tag(name:"summary", value:"HTTP File Server is prone to a remote command execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  neutralization of Null byte or NUL character");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code by uploading a file with certain invalid
  UTF-8 byte sequences that are interpreted as executable macro symbols.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"HttpFileServer version 2.3g and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128593");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69782");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/251276");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39161/");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_http_file_server_detect.nasl");
  script_mandatory_keys("hfs/Installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hfsPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!hfsVer = get_app_version(cpe:CPE, port:hfsPort)){
 exit(0);
}

if(version_is_less_equal(version:hfsVer, test_version:"2.3g"))
{
  report = 'Installed Version: ' + hfsVer + '\n' +
           'Fixed Version: Not available' + '\n';
  security_message(port:hfsPort, data:report);
  exit(0);
}
