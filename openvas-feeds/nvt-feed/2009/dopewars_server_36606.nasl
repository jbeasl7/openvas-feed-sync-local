# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100305");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-10-15 20:14:59 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3591");
  script_name("Dopewars Server 'REQUESTJET' Message Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports(7902);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36606");
  script_xref(name:"URL", value:"http://dopewars.svn.sourceforge.net/viewvc/dopewars?view=rev&revision=1033");

  script_tag(name:"solution", value:"Fixes are available in the SVN repository. Please see the references
  for details.");

  script_tag(name:"summary", value:"Dopewars is prone to a denial of service (DoS) vulnerability
  that affects the server part of the application.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"This issue affects Dopewars 1.5.12, other versions may also be
  affected.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("misc_func.inc");

port = 7902;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

vt_strings = get_vt_strings();

req = string(vt_strings["default"], "^^Ar1111111\n^^Ac", vt_strings["default"], "\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:50);
close(soc);
if(!buf)
  exit(0);

if("^" >< buf[0]) {
  if(!version = eregmatch(pattern:"\^Ak([0-9.]+)\^", string:buf))
    exit(0);

  if(isnull(version[1]))
    exit(0);

  if(version_is_equal(version:version[1], test_version:"1.5.12")) {
    report = report_fixed_ver(installed_version:version[1], vulnerable_range:"Equal to 1.5.12");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
