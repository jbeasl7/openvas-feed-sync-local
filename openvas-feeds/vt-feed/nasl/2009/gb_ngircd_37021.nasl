# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100347");
  script_version("2026-11-17T05:40:57+0000");
  script_cve_id("CVE-2009-4652");
  script_tag(name:"last_modification", value:"2026-11-17 05:40:57 +0000 (Tue, 17 Nov 2026)");
  script_tag(name:"creation_date", value:"2009-11-16 11:47:06 +0100 (Mon, 16 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_name("ngIRCd 13.x < 14.1 SSL/TLS Support MOTD Request Multiple DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("ircd_tcp_detect.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("ircd/banner");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210127194753/http://www.securityfocus.com/bid/37021");
  script_xref(name:"URL", value:"https://web.archive.org/web/20100317150514/http://arthur.barton.de/cgi-bin/gitweb.cgi?p=ngircd.git;a=commit;h=627b0b713c52406e50c84bb9459e7794262920a2");

  script_tag(name:"summary", value:"ngIRCd is prone to multiple denial of service (DoS)
  vulnerabilities when the server is running with SSL/TLS support.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can leverage these issues to crash the server and deny
  access to legitimate users.");

  script_tag(name:"affected", value:"ngIRCd 13 through ngIRCd 14 are known to be vulnerable.");

  script_tag(name:"solution", value:"Update to version 14.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("port_service_func.inc");
include("version_func.inc");

port = service_get_port(default:6667, proto:"irc");

banner = get_kb_item("irc/banner/" + port);
if(!banner || "ngircd" >!< banner)
  exit(0);

version = eregmatch(pattern:"ngircd-([0-9.]+[~rc0-9]*)\.+", string:banner);

if(!isnull(version[1])) {

  if("~" >< version[1]) {
    vers = str_replace(string:version[1], find:string("~"), replace:".");
  } else {
    vers = version[1];
  }

  if(vers =~ "^13\." || vers =~ "^14\.rc") {
    report = report_fixed_ver(installed_version:vers, fixed_version:"14.1");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
