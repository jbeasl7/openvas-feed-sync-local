# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900195");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2713");
  script_name("Sun Java System Access Manager Information Disclosure vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_sjs_access_manager_detect.nasl");
  script_mandatory_keys("Sun/JavaSysAccessManger/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35961");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2176");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-255968-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-126356-03-1");

  script_tag(name:"impact", value:"Successful exploitation could allow remote unprivileged user to gain the
  sensitive information.");

  script_tag(name:"affected", value:"Java System Access Manager version 7.0 2005Q4 and 7.1");

  script_tag(name:"insight", value:"Error in CDCServlet component is caused when 'Cross Domain Single Sign On'
  (CDSSO) is enabled which does not ensure that 'policy advice' is presented
  to the correct client, which can be exploited via unspecified vectors.");

  script_tag(name:"summary", value:"Java System Access Manager is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Apply the security updates from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: The version check below is completely broken...

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

am_port = http_get_port(default:8080);

amVer = get_kb_item("www/" + am_port + "/Sun/JavaSysAccessManger");
amVer = eregmatch(pattern:"^(.+) under (/.*)$", string:amVer);

if(amVer[1] =~ "7.1|7.0.2005Q4"){
  security_message(am_port);
}
