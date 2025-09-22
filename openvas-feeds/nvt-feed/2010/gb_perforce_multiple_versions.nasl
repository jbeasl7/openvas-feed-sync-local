# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100521");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2010-0934");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-03-09 14:33:24 +0100 (Tue, 09 Mar 2010)");
  script_name("Perforce Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38595");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56738");
  script_xref(name:"URL", value:"http://www.perforce.com/perforce/products/p4web.html");
  script_xref(name:"URL", value:"http://resources.mcafee.com/forms/Aurora_VDTRG_WP");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("perforce_detect.nasl");
  script_require_ports("Services/perforce", 1666);
  script_mandatory_keys("perforce/detected");

  script_tag(name:"summary", value:"Perforce Server is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  1. A security bypass vulnerability.

  Attackers may exploit the issue to bypass certain security restrictions and perform unauthorized
  actions.

  2. A session-hijacking vulnerability.

  An attacker can exploit this issue to gain access to the affected application.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("version_func.inc");
include("port_service_func.inc");

port = service_get_port(default:1666, proto:"perforce");

if(!vers = get_kb_item("perforce/" + port + "/version"))
  exit(0);

if(!isnull(vers)) {

  if(!version = split(vers, sep:"/", keep:FALSE))
    exit(0);

  if(version_is_equal(version:version[2], test_version:"2009.2") ||
     version_is_equal(version:version[2], test_version:"2007.2") ||
     version_is_equal(version:version[2], test_version:"2007.1") ||
     version_is_equal(version:version[2], test_version:"2006.2") ||
     version_is_equal(version:version[2], test_version:"2006.1")) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
