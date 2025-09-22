# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.14260");
  script_version("2022-01-13T15:13:27+0000");
  script_tag(name:"last_modification", value:"2022-01-13 15:13:27 +0000 (Thu, 13 Jan 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nikto (NASL wrapper)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"This VT is deprecated.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
