# SPDX-FileCopyrightText: 2002 Thomas Reinke
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10948");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2811");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2001-1046");
  script_name("qpopper options buffer overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Thomas Reinke");
  script_family("Buffer overflow");
  script_dependencies("popserver_detect.nasl");
  script_require_ports("Services/pop3", 110, 995);
  script_mandatory_keys("pop3/qpopper/detected");

  script_tag(name:"solution", value:"Upgrade to the latest version, or disable
  processing of user option files.");

  script_tag(name:"summary", value:"The remote qpopper server, according to its banner, is
  running version 4.0.3 or version 4.0.4. These versions
  are vulnerable to a buffer overflow if they are configured
  to allow the processing of a user's ~/.qpopper-options file.");

  script_tag(name:"impact", value:"A local user can cause a buffer overflow by setting the
  bulldir variable to something longer than 256 characters.");

  script_tag(name:"vuldetect", value:"This test could not confirm the existence of the problem - it relied on the banner being returned.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pop3_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = pop3_get_port(default:110);
banner = pop3_get_banner(port:port);
if(!banner || "Qpopper" >!< banner)
  exit(0);

if(ereg(pattern:".*Qpopper.*version (4\.0\.[34]).*", string:banner, icase:TRUE)) {
  security_message(port:port);
  exit(0);
}

exit(99);
