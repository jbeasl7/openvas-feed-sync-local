# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800940");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7155");
  script_name("NetRisk Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/39465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27150");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2008-7155");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/27150.pl");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netrisk_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netrisk/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  security restrictions and change the password of arbitrary users via direct request.");

  script_tag(name:"affected", value:"NetRisk version 1.9.7 and prior.");

  script_tag(name:"insight", value:"The vulnerability is caused because the application does not
  properly restrict access to 'admin/change_submit.php'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NetRisk is prone to a security bypass vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

netriskPort = http_get_port(default:80);

netriskVer = get_kb_item("www/" + netriskPort + "/NetRisk");
netriskVer = eregmatch(pattern:"^(.+) under (/.*)$", string:netriskVer);

if(netriskVer[1] != NULL)
{
  if(version_is_less_equal(version:netriskVer[1], test_version:"1.9.7")){
    security_message(netriskPort);
  }
}
