# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800387");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6565");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Invision Power Board Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41502");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/490115");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("invision_power_board/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers execute arbitrary code in the
context of the affected web application and can cause various web related attacks by point to malicious IFRAME or
HTML data.");

  script_tag(name:"affected", value:"Invision Power Board version 2.3.1 and prior.");

  script_tag(name:"insight", value:"Improper sanitization of user supplied input in the signature data which can
cause crafting malicious IFRAME or HTML tags to gain sensitive information about the web application or can cause
injection of web pages to the web application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Invision Power Board is prone to a cross-site scripting (XSS) vulnerability.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!ipbPort = get_app_port(cpe:CPE))
  exit(0);

if (!ipbVer = get_app_version(cpe:CPE, port:ipbPort))
  exit(0);

if (version_is_less_equal(version: ipbVer, test_version: "2.3.1")) {
  security_message(port: ipbPort);
  exit(0);
}

exit(0);
