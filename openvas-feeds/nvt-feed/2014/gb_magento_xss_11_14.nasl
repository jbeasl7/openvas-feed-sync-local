# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105110");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-2461"); # nb: Flex CVE for the vulnerable swfs used in Magento

  script_name("Magento XSS Vulnerability");

  script_xref(name:"URL", value:"http://appcheck-ng.com/unpatched-vulnerabilites-in-magento-e-commerce-platform/");
  script_xref(name:"URL", value:"https://peterocallaghan.co.uk/2016/07/magento-csrf-vulnerability-via-adobe-flex/");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to
steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Check the md5sum of the affected .swf files");
  script_tag(name:"solution", value:"Update the EE to version 1.14 or the CE to 1.9.1.0. Make sure that
 the mentioned files are removed from the installation during the update process.");
  script_tag(name:"summary", value:"Magento is prone to multiple cross-site scripting vulnerabilities because it
fails to sanitize user supplied input.");

  script_tag(name:"affected", value:"Magento 1.9.0.1. Previous versions may also affected.");

  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-11-05 19:20:13 +0100 (Wed, 05 Nov 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("sw_magento_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magento/installed");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

urls = make_array('/skin/adminhtml/default/default/media/editor.swf',         '259afd515d7b2edee76f67973fea95a6',
                  '/skin/adminhtml/default/default/media/uploader.swf',       '1c300001dadd932ef6e33a2fadf941e1',
                  '/skin/adminhtml/default/default/media/uploaderSingle.swf', '304dd960698c5786dcd64b0e138f80ca'
                 );

foreach url ( keys( urls ) )
{
  path = dir + url;

  req = http_get( item:path, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( buf && hexstr( MD5( buf ) ) == urls[url] )
  {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
