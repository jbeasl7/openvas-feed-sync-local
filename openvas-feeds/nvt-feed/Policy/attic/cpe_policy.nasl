# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100353");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CPE-based Policy Check");
  # nb: Only put into ACT_END to stay consistent with the replacement VTs.
  script_category(ACT_END);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Policy");

  script_tag(name:"summary", value:"This VT is running CPE-based Policy Checks.

  ATTENTION: This VT is deprecated. Please use the new set of 4 VTs to handle CPE policies which are
  to be found in the family 'Policy'.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

exit(66);
