# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103724");
  script_cve_id("CVE-2013-3634", "CVE-2013-3633");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_version("2025-04-22T10:32:18+0000");

  script_name("Siemens Scalance X200 Series Switches Multiple Vulnerabilities (SSA-170686)");

  script_xref(name:"URL", value:"https://cert-portal.siemens.com/productcert/html/ssa-170686.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60165");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60168");

  script_tag(name:"last_modification", value:"2025-04-22 10:32:18 +0000 (Tue, 22 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-05-30 17:50:28 +0200 (Thu, 30 May 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone AG");

  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports(23);
  script_mandatory_keys("telnet/siemens/scalance_x200/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Siemens Scalance X200 series switches are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  1. a remote security bypass vulnerability.

  An attacker can exploit this issue to bypass certain security
  restrictions and execute SNMP commands without proper credentials.

  2. a remote privilege escalation vulnerability.

  An attacker can exploit this issue to gain elevated privileges
  within the application and execute commands with escalated privileges.");

  exit(0);
}

include("telnet_func.inc");
include("version_func.inc");
include("misc_func.inc");
include("dump.inc");

port = 23;
if(!get_port_state(port))exit(0);
banner = telnet_get_banner(port:port);

if(!banner || "SCALANCE X200" >!< banner || "Device type" >!< banner || "Firmware" >!< banner)
  exit(0);

dv = eregmatch(pattern:string("Device type.*:.*SCALANCE ([^\r\n ]+)"), string:banner);
if(isnull(dv[1]))exit(0);

device = dv[1];

vuln_devices = make_list("X204","X202-2","X201-3","X200-4");

foreach vd (vuln_devices) {

  if(vd == device) {
    affected_device = TRUE;
    break;
  }
}

if(!affected_device)exit(0);

fw = eregmatch(pattern:string("Firmware.*: V ([^\r\n ]+)"), string:banner);
if(isnull(fw[1]))exit(0);

firmware = fw[1];

if(version_is_less(version:firmware, test_version:"5.1.0")) {
  security_message(port:port);
  exit(0);
}

exit(99);
