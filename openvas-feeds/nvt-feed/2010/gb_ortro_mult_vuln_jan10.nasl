# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800981");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4519");
  script_name("Ortro Multiple Unspecified Vulnerabilities");
  script_xref(name:"URL", value:"http://www.ortro.net/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54026");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3057");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ortro_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ortro/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker Disable/Lock a host and
  to perform scp transfer between two remote hosts.");

  script_tag(name:"affected", value:"Ortro version prior to 1.3.4.");

  script_tag(name:"insight", value:"The flaw is caused by unspecified errors with unknown impact and attack
  vectors.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Ortro version 1.3.4.");

  script_tag(name:"summary", value:"Ortro is prone to multiple unspecified vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

ortroPort = http_get_port(default:80);

ortroVer = get_kb_item("www/"+ ortroPort + "/Ortro");
if(!ortroVer)
  exit(0);

ortroVer  = eregmatch(pattern:"^(.+) under (/.*)$", string:ortroVer);
if(ortroVer[1] != NULL)
{
  if(version_is_less(version:ortroVer[1], test_version:"1.3.4")){
    report = report_fixed_ver(installed_version:ortroVer[1], fixed_version:"1.3.4");
    security_message(port:ortroPort, data:report);
  }
}
