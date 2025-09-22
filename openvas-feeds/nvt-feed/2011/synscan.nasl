# Copyright (C) 2011 Greenbone Networks GmbH
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

# nb: This VT was previously a binary ".nes" and had a copyright to Renaud Deraison, this Copyright
# was changed to Greenbone Networks GmbH while rewriting the VT in 2011 as it is basically a "new" VT now.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11219");
  script_version("2022-01-13T15:37:06+0000");
  script_tag(name:"last_modification", value:"2022-01-13 15:37:06 +0000 (Thu, 13 Jan 2022)");
  script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SYN Scan");
  script_category(ACT_SCANNER);
  script_family("Port scanners");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"This plugins performs a supposedly fast SYN port scan.

  It does so by computing the RTT (round trip time) of the packets coming back and forth between the
  scanner host and the target, then it uses that to quickly send SYN packets to the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

plugin_run_synscan();

exit(0);