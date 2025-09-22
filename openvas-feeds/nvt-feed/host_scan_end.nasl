# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103739");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-06-17 10:52:11 +0100 (Mon, 17 Jun 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Host Scan End");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");

  script_tag(name:"summary", value:"This routine is the last action of scanning a host.

  It stores information about the applied VT Feed and Version as well as the applied Scanner
  version. Finally the time of finishing the scan of this host is determined and stored.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

SCRIPT_DESC = "Host Scan End";

include("host_details.inc");
include("misc_func.inc");
include("plugin_feed_info.inc");

if(OPENVAS_VERSION)
  register_host_detail(name:"scanned_with_scanner", value:OPENVAS_VERSION, desc:SCRIPT_DESC);

if(PLUGIN_SET)
  register_host_detail(name:"scanned_with_feedversion", value:PLUGIN_SET, desc:SCRIPT_DESC);

if(PLUGIN_FEED)
  register_host_detail(name:"scanned_with_feedtype", value:PLUGIN_FEED, desc:SCRIPT_DESC);

if(FEED_NAME)
  register_host_detail(name:"scanned_with_feedname", value:FEED_NAME, desc:SCRIPT_DESC);
else
  register_host_detail(name:"scanned_with_feedname", value:"None / Empty", desc:SCRIPT_DESC);

if(FEED_VENDOR)
  register_host_detail(name:"scanned_with_feedvendor", value:FEED_VENDOR, desc:SCRIPT_DESC);
else
  register_host_detail(name:"scanned_with_feedvendor", value:"None / Empty", desc:SCRIPT_DESC);

if(gos_version = get_local_gos_version())
  register_host_detail(name:"scanned_with_gosversion", value:gos_version, desc:SCRIPT_DESC);

# This stop time is only used by other VTs. The scanner will determine the actual stop time that
# will then be reported to the scanner client.
set_kb_item(name:"/tmp/stop_time", value:unixtime());

exit(0);
