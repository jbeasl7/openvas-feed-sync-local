# Copyright (C) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105974");
  script_version("2022-07-18T10:11:09+0000");
  script_tag(name:"last_modification", value:"2022-07-18 10:11:09 +0000 (Mon, 18 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-03-11 11:09:56 +0700 (Wed, 11 Mar 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("QMTP Open Relay Test");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("qmtp_detect.nasl", "smtp_settings.nasl"); # nb: The setting for get_3rdparty_domain() is currently located in this VT.
  script_require_ports("Services/QMTP", "Services/QMQP", 209, 628);

  script_tag(name:"summary", value:"The QMTP/QMQP server accepts relaying.");

  script_tag(name:"vuldetect", value:"Send a relay request and check the response.");

  script_tag(name:"insight", value:"The QMTP/QMQP server is configured to accept relaying.");

  script_tag(name:"impact", value:"Spammers might use the server to relay spam over this server.");

  script_tag(name:"solution", value:"Improve the configuration of your QMTP/QMQP server so that it
  cannot be used as a relay anymore.");

  exit(0);
}

include("misc_func.inc");
include("network_func.inc");
include("port_service_func.inc");
include("smtp_func.inc");

ports = service_get_ports(default_port_list:make_list(209, 628), proto:"QMTP");

function netstr(str)
{
  local_var l;

  l = strlen(str);
  return strcat(l, ":", str, ",");
}

vt_strings = get_vt_strings();
lowercase = vt_strings["lowercase"];
default = vt_strings["default"];
domain = get_3rdparty_domain();

foreach port (ports) {
  if (service_is_unknown(port: port)) {
    soc = open_sock_tcp(port);
    if (soc) {
      msg = strcat(netstr(str: "
Message-ID: <1234567890.666." + lowercase + "@" + domain + ">
From: " + lowercase + "@" + domain + "
To: postmaster@" + domain + "

" + default + " is probing this server.
"), netstr(str: lowercase + "@" + domain), netstr(str: netstr(str: "postmaster@" + domain)));

      # QMQP encodes the whole message once more
      if (port == 628) {
        msg = netstr(str: msg);
        srv = "QMQP";
      }
      else
        srv = "QMTP";

      send(socket: soc, data: msg);
      r = recv(socket: soc, length: 1024);
      close(soc);

      if (ereg(pattern: "^[1-9][0-9]*:K", string: r)) {
        # K: Message accepted for delivery
        # Z: temporary failure
        # D: permanent failure
        if (is_private_addr(addr: get_host_ip()) ||
            is_private_addr(addr: this_host()) )
          report = 'The ' + srv + ' server accepts relaying. Make sure it rejects connections from ' +
                   'the internet so that spammers cannot use it as an open relay.';
        else
          report = 'The ' + srv + ' server accepts relaying on or from internet. Spammers can use ' +
                   'it as an open relay.';
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(0);
