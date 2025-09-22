# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802243");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_cve_id("CVE-2010-4826", "CVE-2010-4827");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Snitz Forums 2000 'members.asp' SQL Injection and Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45381");
  script_xref(name:"URL", value:"http://forum.snitz.com/forum/topic.asp?TOPIC_ID=69770");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("snitz_forums_2000_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("snitzforums/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Snitz Forums 2000 version 3.4.07.");

  script_tag(name:"insight", value:"- Input passed to the 'M_NAME' parameter in members.asp is not properly
  sanitised before being returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in
  context of an affected site.

  - Input passed to the 'M_NAME' parameter in members.asp is not properly
  sanitised before being used in SQL queries. This can be exploited to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"summary", value:"Snitz is prone to SQL injection and cross site scripting vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://forum.snitz.com/forum/topic.asp?TOPIC_ID=69770");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

ver = get_version_from_kb(port:port, app:"SnitzForums");
if(ver)
{
  if(version_is_equal(version:ver, test_version:"3.4.07")){
    report = report_fixed_ver(installed_version:ver, vulnerable_range:"Equal to 3.4.07");
    security_message(port:port, data:report);
  }
}
