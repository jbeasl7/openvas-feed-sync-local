# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108202");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2017-08-07 08:00:00 +0200 (Mon, 07 Aug 2017)");
  script_name("Microsoft Exchange Server End of Life (EOL) Detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ms_exchange_server_detect.nasl",
                      "gb_microsoft_exchange_outlook_web_app_http_detect.nasl");
  script_mandatory_keys("microsoft/exchange_server/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/lifecycle/products/?terms=%22exchange%20server%22");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/lifecycle/products/exchange-server-2019");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/lifecycle/products/exchange-server-2016");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/lifecycle/products/exchange-server-2013");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/lifecycle/products/exchange-server-2010");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/lifecycle/products/exchange-server-2007");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/lifecycle/products/exchange-server-2003");

  script_tag(name:"summary", value:"The Microsoft Exchange Server version on the remote
  host has reached the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.

  Note: This VT is also checking the EOL status of an Exchange Server version based on an
  exposed Outlook Web App / Outlook Web Access (OWA).");

  script_tag(name:"impact", value:"An EOL version of Microsoft Exchange Server is not
  receiving any security updates from the vendor. Unfixed security vulnerabilities might
  be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"affected", value:"All EOL versions of Microsoft Exchange Server. Please see the
  references for a full list of EOL versions.");

  script_tag(name:"solution", value:"Update the Microsoft Exchange Server version on the
  remote host to a newer version of Exchange on your on-premises servers or migrate to
  Office 365 using cutover, staged, or hybrid migration.

  Note: Please create an override for this result if a Microsoft Exchange Server version is covered
  by the Extended Security Updates (ESU) program and if such is enabled on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:microsoft:exchange_server", "cpe:/a:microsoft:outlook_web_app" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

# nb:
# - gb_microsoft_exchange_outlook_web_app_http_detect.nasl is also setting this CPE but currently
#   with a different version scheme
# - This wouldn't match the versions of the Exchange CPE as used in eol_product.inc so we need to
#   skip this CPE for now. This is done by exiting here if port > 0 because the local detections of
#   Exchange are setting the port as "0".
# - For the OWA CPE a dedicated entry in eol_product.inc exists
#
if( "cpe:/a:microsoft:exchange_server" >< cpe && port )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:cpe, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];

if( ret = product_reached_eol( cpe:cpe, version:version ) ) {
  report = eol_build_message( name:"Microsoft Exchange Server",
                              cpe:cpe,
                              version:version,
                              location:infos["location"],
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
