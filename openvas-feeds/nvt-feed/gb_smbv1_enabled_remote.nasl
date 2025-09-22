# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140151");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2017-02-04 09:33:13 +0100 (Sat, 04 Feb 2017)");
  script_name("SMBv1 Enabled - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Service detection");
  script_dependencies("gb_smb_version_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("smb_v1/supported");

  script_xref(name:"URL", value:"https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2696547");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/204279");

  script_tag(name:"summary", value:"The host has enabled SMBv1 for the SMB Server.");

  script_tag(name:"vuldetect", value:"Checks if SMBv1 is enabled for the SMB Server based on the
  information provided by the following VT:

  - SMB Remote Version Detection (OID: 1.3.6.1.4.1.25623.1.0.807830).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");

port = kb_smb_transport();
if( ! port )
  port = 139;

if( get_kb_item( "smb_v1/" + port + "/supported" ) ) {
  log_message( port:port, data:"SMBv1 is enabled for the SMB Server" );
}

exit( 0 );
