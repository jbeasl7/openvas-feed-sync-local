# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# nb: Initially this was a single VT covering CVE-2012-3013 (for HTTP) and CVE-2012-4879 (for
# Telnet) which was checking both protocols in one go. For best practices and performance reasons
# this VT has been split into two while keeping the creation_date() in both (on purpose, technically
# speaking both parts got created back then).

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104502");
  script_cve_id("CVE-2012-4879");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-04-12 11:29:33 +0200 (Thu, 12 Apr 2012)");
  script_name("WAGO I/O System 758 Series Hard-Coded Credentials Vulnerability (Telnet)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/wago/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.cisa.gov/uscert/ics/advisories/ICSA-12-249-02");
  script_xref(name:"URL", value:"https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-12-097-01");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52940");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52942");
  script_xref(name:"URL", value:"http://www.wago.com/wagoweb/documentation/app_note/a1176/a117600e.pdf");

  script_tag(name:"summary", value:"WAGO I/O System 758 series devices are using a set of hard-coded
  credentials.");

  script_tag(name:"vuldetect", value:"Tries to login via Telnet using known default or hard-coded
  credentials.");

  script_tag(name:"impact", value:"Successful attacks can allow a remote attacker to gain
  unauthorized access to the vulnerable device, using the Telnet service.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("port_service_func.inc");

credentials = make_list("root:admin", "admin:admin", "user:user", "user:user00", "guest:guest");

port = telnet_get_port(default:23);

foreach credential(credentials) {

  if(!soc = open_sock_tcp(port))
    continue;

  res = telnet_negotiate(socket:soc);
  if(!res) {
    close(soc);
    continue;
  }

  if("WagoIPC1 login" >!< res) {
    close(soc);
    break;
  }

  cred = split(credential, sep:":", keep:FALSE);
  user = cred[0];
  pass = cred[1];

  send(socket:soc, data:user + '\n');
  res = recv(socket:soc, length:512);
  if(!res || "Password" >!< res) {
    close(soc);
    continue;
  }

  send(socket:soc, data:pass + '\n');
  res = recv(socket:soc, length:512);
  if(!res || "-sh" >!< res) {
    close(soc);
    continue;
  }

  report = 'It was possible to login using the following credentials: (Username:Password)\n' + credential;

  send(socket:soc, data:'su\n');
  res = recv(socket:soc, length:512);
  if(res && "Password" >< res) {
    send(socket:soc, data:'ko2003wa\n');
    res = recv(socket:soc, length:512);
    if(res && "this is the super user account" >< res) {
      report += '\nAfter it was possible to login using default credentials it was also possible to "su" to the super user account using "ko2003wa" as password.';
    }
  }

  close(soc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
