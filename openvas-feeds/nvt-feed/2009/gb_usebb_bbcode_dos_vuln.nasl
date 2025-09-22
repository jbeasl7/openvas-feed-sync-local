# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901057");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4041");
  script_name("UseBB BBcode Parsing Remote Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37328");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37010");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3222");
  script_xref(name:"URL", value:"http://www.usebb.net/community/topic-post9775.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_usebb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("usebb/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code and cause Denial-of-Service by posting a message containing specially crafted BBcode.");

  script_tag(name:"affected", value:"UseBB version 1.0.9 and prior on all platforms.");

  script_tag(name:"insight", value:"This issue is due to an infinite loops while parsing for malformed
  BBcode.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to UseBB version 1.0.10.");

  script_tag(name:"summary", value:"UseBB is prone to a denial of service (DoS)
  vulnerability.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

usebbPort = http_get_port(default:80);

usebbVer = get_kb_item("www/"+ usebbPort + "/UseBB");
if(!usebbVer)
  exit(0);

usebbVer = eregmatch(pattern:"^(.+) under (/.*)$", string:usebbVer);
if(usebbVer[1])
{
  if(version_is_less(version:usebbVer[1], test_version:"1.0.10")){
    report = report_fixed_ver(installed_version:usebbVer[1], fixed_version:"1.0.10");
    security_message(port: usebbPort, data: report);
  }
}
