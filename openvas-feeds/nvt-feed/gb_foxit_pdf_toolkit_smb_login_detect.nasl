# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810522");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-01-25 15:52:27 +0530 (Wed, 25 Jan 2017)");

  script_name("Foxit PDF Toolkit Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_login.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("login/SMB/success");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"SMB login and WMI file search based detection of Foxit PDF
  Toolkit.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

query = "-Filter \" + raw_string( 0x22 ) + "FileName = 'fhtml2pdf' AND Extension = 'exe'" + '\\"';
results = powershell_wmi_query( classname:"CIM_DataFile", class_args:query, properties:"Manufacturer, Name, Version", force_wmi_object:TRUE );

if( "Foxit Software Inc" >< results ) {
  info = split( results, sep:";", keep:FALSE );
  version = info[2];
  path = info[1];
  if( version ) {
    set_kb_item( name:"foxit/pdf_toolkit/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:foxit_pdf_toolkit:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:foxitsoftware:foxit_pdf_toolkit";

    register_product( cpe:cpe, location:path );

    log_message( data:build_detection_report( app:"Foxit PDF Toolkit",
                                              version:version,
                                              install:path,
                                              cpe:cpe,
                                              concluded:results ) );
  }
}

exit( 0 );