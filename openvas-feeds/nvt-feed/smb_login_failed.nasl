# Copyright (C) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106091");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-06-03 10:44:56 +0700 (Fri, 03 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMB Login Failed For Authenticated Checks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_login.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("login/SMB/failed");

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#requirements-on-target-systems-with-microsoft-windows");

  script_tag(name:"summary", value:"It was NOT possible to login using the provided SMB
  credentials. Hence authenticated checks are NOT enabled.");

  script_tag(name:"solution", value:"Recheck the SMB credentials and configuration for authenticated checks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");

port = get_kb_item("login/SMB/failed/port");
if (!port)
  port = kb_smb_transport();

log_message(port: port);
exit(0);
