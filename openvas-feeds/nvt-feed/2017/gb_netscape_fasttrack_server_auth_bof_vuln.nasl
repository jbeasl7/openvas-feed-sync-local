# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netscape:fasttrack_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811546");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-1999-0853");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-28 15:05:05 +0530 (Fri, 28 Jul 2017)");
  script_name("Netscape FastTrack Server Authentication Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Netscape FastTrack Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  HTTP Basic Authentication procedure for the servers, which has a buffer overflow
  condition when a long username or password (over 508 characters) are provided.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain root privileges under UNIX and SYSTEM privileges under NT.");

  script_tag(name:"affected", value:"Netscape FastTrack Server 3.01.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://cve.circl.lu/cve/CVE-1999-0853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/847");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_netscape_server_detect.nasl");
  script_mandatory_keys("netscape/fasttrack_server/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!netport = get_app_port(cpe: CPE))
  exit(0);

if(!netVer = get_app_version(cpe:CPE, port:netport))
  exit(0);

if(netVer == "3.01") {
  report = report_fixed_ver(installed_version:netVer, fixed_version:"WillNotFix");
  security_message(data:report, port:netport);
  exit(0);
}

exit(99);
