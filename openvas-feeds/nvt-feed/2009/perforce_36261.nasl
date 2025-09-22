# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100269");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-07 09:47:24 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0929");

  script_name("Perforce Multiple Unspecified Remote Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36261");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("perforce_detect.nasl");
  script_require_ports("Services/perforce", 1666);
  script_mandatory_keys("perforce/detected");

  script_tag(name:"summary", value:"Perforce Server is prone to multiple unspecified remote security
  vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Multiple unspecified denial-of-service vulnerabilities

  - An unspecified vulnerability");

  script_tag(name:"impact", value:"An attacker can exploit these issues to crash the affected
  application, denying service to legitimate users. Other attacks are also possible.");

  script_tag(name:"affected", value:"Perforce 2008.1/160022 is vulnerable, other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

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

  if(version[2] >!< "2008.1")
    exit(99);

  if(version_is_equal(version:version[3], test_version:"160022")) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
