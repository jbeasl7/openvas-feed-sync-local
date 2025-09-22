# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105312");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-02 16:13:36 +0200 (Thu, 02 Jul 2015)");
  script_name("wedgeOS Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of wedgeOS");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("wedgeOS/status");
  exit(0);
}

include("host_details.inc");

status = get_kb_item("wedgeOS/status");
# BeSecure NDP-VM Version 5.0.0-206
# Service: WebFilter SmartFilter online success
# Scanner: SMTP       online
# Scanner: POP3       online
# Scanner: IMAP       online
# Scanner: HTTP       online
# Scanner: ICAP       disabled
# SubSonic is disabled
# HTTP SubSonic is enabled
# SMTP SubSonic is enabled
# POP3 SubSonic is enabled
# IMAP SubSonic is enabled

if( "BeSecure" >!< status ) exit( 0 );

cpe = 'cpe:/a:wedge_networks:wedgeos';
vers = 'unknown';
install = 'ssh';

version = eregmatch( pattern:"Version ([0-9.-]+)", string:status );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:install );

log_message( data: build_detection_report( app:"wedgeOS",
                                           version:vers,
                                           install:install,
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:0 );

exit(0);

