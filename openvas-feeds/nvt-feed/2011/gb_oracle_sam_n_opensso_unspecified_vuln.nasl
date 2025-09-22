# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902282");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-4444");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Oracle Java Access Manager And OpenSSO Unspecified Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_opensso_detect.nasl", "secpod_sjs_access_manager_detect.nasl");
  script_mandatory_keys("JavaSysAccessManger_or_OracleOpenSSO/detected");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2011.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45884");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to affect
  confidentiality and integrity via unknown vectors.");

  script_tag(name:"affected", value:"Sun OpenSSO Enterprise version 8.0,

  Java System Access Manager version 7.0 and 7.1");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors in the application, which allows
  remote attackers to affect confidentiality and integrity via unknown vectors.");

  script_tag(name:"summary", value:"Access Manager or OpenSSO is prone to an unspecified vulnerability.");

  script_tag(name:"solution", value:"Apply the security updates.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: The version check below is completely broken...

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

am_port = http_get_port(default:8080);

amVer = get_kb_item("www/" + am_port + "/Sun/JavaSysAccessManger");
amVer = eregmatch(pattern:"^(.+) under (/.*)$", string:amVer);

if(amVer[1] =~ "(7\.0|7\.1)")
{
  security_message(am_port);
  exit(0);
}

ssoVer = get_kb_item("www/" + am_port + "/Sun/OpenSSO");
ssoVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ssoVer);

if(ssoVer[1] =~ "^8\.0"){
  security_message(am_port);
}
