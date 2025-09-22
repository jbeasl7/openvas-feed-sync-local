# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170204");
  script_version("2025-06-27T15:42:32+0000");
  script_tag(name:"last_modification", value:"2025-06-27 15:42:32 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"creation_date", value:"2022-10-28 12:56:06 +0000 (Fri, 28 Oct 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("UPnP Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Service detection");
  script_dependencies("gb_upnp_udp_detect.nasl", "find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 52881);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"TCP based detection of the UPnP protocol.

  The script sends a HTTP request to URLs for the root description XML, either based on previously
  detected location or a list of known possible locations.");

  script_xref(name:"URL", value:"https://openconnectivity.org/foundation/faq/upnp-faq/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("http_keepalive.inc");

function handleUPnPXML( xml, port ) {

  local_var xml, port;
  local_var extra, manufacturer, model_name, friendly_name, model_number, model_type, model_description, version, software_version, display_version, software_generation, hardware_version;

  extra = NULL;

  set_kb_item( name:"upnp/tcp/port", value:port );

  #<device>
  #  <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
  #  <friendlyName>SR1217 (DS216se)</friendlyName>
  #  <manufacturer>Synology</manufacturer>
  #  <manufacturerURL>http://www.synology.com</manufacturerURL>
  #  <modelDescription>Synology NAS</modelDescription>
  #  <modelName>DS216se</modelName>
  #  <modelNumber>DS216se 6.2-25556</modelNumber>
  #  <modelURL>http://www.synology.com</modelURL>
  #  <modelType>NAS</modelType>
  #  <serialNumber>redacted</serialNumber>
  #
  # or:
  #
  # <netRemote>
  # <friendlyName>ir110</friendlyName>
  # <version>ir-mmi-FS2026-0500-0084_V2.11.16.EX69632-2A10</version>
  # <webfsapi>http://<redacted>:80/fsapi</webfsapi>
  # </netRemote>
  #
  # or:
  #
  #<device>
  #<deviceType>urn:schemas-upnp-org:device:ZonePlayer:1</deviceType>
  #<friendlyName>76.206.43.58 - Sonos Bridge</friendlyName>
  #<manufacturer>Sonos, Inc.</manufacturer>
  #<manufacturerURL>http://www.sonos.com</manufacturerURL>
  #<modelNumber>ZB100</modelNumber>
  #<modelDescription>Sonos Bridge</modelDescription>
  #<modelName>Sonos Bridge</modelName>
  #<modelURL>http://www.sonos.com/store/products/ZB100</modelURL>
  #<softwareVersion>57.3-77280</softwareVersion>
  #<swGen>1</swGen>
  #<hardwareVersion>1.5.0.0-1.0</hardwareVersion>
  #<displayVersion>11.2</displayVersion>

  manufacturer = eregmatch( pattern:"<manufacturer>([^<]+)</manufacturer>", string:xml );
  if ( ! isnull( manufacturer[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/manufacturer", value:manufacturer[1] );
    extra = "  Manufacturer:  " + manufacturer[1];
  }

  model_name = eregmatch( pattern:"<modelName>([^<]+)</modelName>", string:xml );
  if ( ! isnull( model_name[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelName", value:model_name[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Model Name:    " + model_name[1];
  }

  friendly_name = eregmatch( pattern:"<friendlyName>([^<]+)</friendlyName>", string:xml );
  if ( ! isnull( friendly_name[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/friendlyName", value:friendly_name[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Friendly Name: " + friendly_name[1];
  }

  model_number = eregmatch( pattern:"<modelNumber>([^<]+)</modelNumber>", string:xml );
  if ( ! isnull( model_number[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelNumber", value:model_number[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Model Number:  " + model_number[1];
  }

  model_type = eregmatch( pattern:"<modelType>([^<]+)</modelType>", string:xml );
  if ( ! isnull( model_type[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelType", value:model_type[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Model Type:    " + model_type[1];
  }

  model_description = eregmatch( pattern:"<modelDescription>([^<]+)</modelDescription>", string:xml );
  if ( ! isnull( model_description[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/modelDescription", value:model_description[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Model Desc:    " + model_description[1];
  }

  version = eregmatch( pattern:"<version>([^<]+)</version>", string:xml );
  if ( ! isnull( version[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/version", value:version[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Version:    " + version[1];
  }

  software_version = eregmatch( pattern:"<softwareVersion>([0-9.-]+)(-manufacturing)?</softwareVersion>", string:xml );
  if ( ! isnull( software_version[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/softwareVersion", value:software_version[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Build Number:  " + software_version[1];
  }

  software_generation = eregmatch( pattern:"<swGen>([0-9])</swGen>", string:xml );
  if ( ! isnull( software_generation[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/softwareGeneration", value:software_generation[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Software Gen:  " + software_generation[1];
  }

  hardware_version = eregmatch( pattern:"<hardwareVersion>([0-9.-]+)</hardwareVersion>", string:xml );
  if ( ! isnull( hardware_version[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/hardwareVersion", value:hardware_version[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  Hardware Ver:  " + hardware_version[1];
  }

  display_version = eregmatch( pattern:"<displayVersion>([0-9.]+)</displayVersion>", string:xml );
  if ( ! isnull( display_version[1] ) ) {
    set_kb_item( name:"upnp/tcp/" + port + "/device/displayVersion", value:display_version[1] );
    if ( ! isnull( extra ) )
      extra += '\n';
    extra += "  App Ver:       " + display_version[1];
  }

  # nb: Save the full XML so that we can possible add more useful info in the KB if required.
  set_kb_item( name:"upnp/tcp/" + port + "/device/full_xml", value:xml );

  return extra;
}

report = "";

# e.g.:
# <root xmlns="urn:schemas-upnp-org:device-1-0">
#   <device>
#     <deviceType>urn:schemas-wifialliance-org:device:WFADevice:1</deviceType>
#   *snip*
#   </device>
# </root>
#
# or "just" the following (without the <root><device>*snip*</device></root>):
#
# <netRemote>
# <friendlyName>ir110</friendlyName>
# <version>ir-mmi-FS2026-0500-0084_V2.11.16.EX69632-2A10</version>
# <webfsapi>http://<redacted>/fsapi</webfsapi>
# </netRemote>
#
xml_verification_pattern = "(<root( xmlns=[^>]+)?>.+</root>|<device>.+</device>|[Cc]ontent-[Tt]ype\s*:\s*text/xml.+<[^>]+>.+</[^>]+>)";

if ( location = get_kb_item( "upnp/location" ) ) {
  # eg. LOCATION: http://<redacted>:<redacted>/ssdp/desc-DSM-eth0.xml
  # nb: The part after http(s):// is always an IP, so this can be simplified
  # nb: We're not "verifying" the IP in the location here because e.g. it might point to a local
  # IP address (192.168.x.x) while the port is also "exposed" externally.
  infos = eregmatch( pattern:"LOCATION\s*:\s*https?://[0-9.]+:([0-9]+)(/[-a-zA-Z0-9_/]+\.(xml|jsp))", string:location, icase:TRUE );

  # nb: get_port_state() is used here because we only want to touch the port we got redirected to if
  # it was scanned by a port scanner previously.
  if ( ! isnull( infos[2] ) && get_port_state( infos[1] ) ) {

    port = infos[1];
    url = infos[2];
    res = http_get_cache( item:url, port:port );

    if ( res && res =~ "^HTTP/(1\.[01]|2) 200" && eregmatch( string:res, pattern:xml_verification_pattern, icase:FALSE ) ) {
      extra = handleUPnPXML( xml:res, port:port );
      set_kb_item( name:"upnp/tcp/" + port + "/location", value:url );

      # nb: Later used to not touch the same port twice
      loc_port = port;

      report  = "The remote Host exposes an UPnP root device XML on port " + port + '/tcp.\n';
      report += '\nThe XML can be found at the location:\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      if ( ! isnull( extra ) )
        report += '\n\nExcerpt from the obtained data:\n' + extra;

      service_register( port:port, ipproto:"tcp", proto:"upnp" );
      log_message( data:report, port:port, proto:"tcp" );
    }
  }
}

xml_locations = make_list( "/simplecfg.xml",
                           "/rootDesc.xml",
                           "/devdescr.xml",
                           "/gateway.xml",
                           "/devicedesc.xml",
                           "/description.xml",
                           "/ssdp/device-desc.xml",
                           "/XD/DeviceDescription.xml",
                           "/DeviceDescription.xml",
                           "/xml/device_description.xml",
                           "/device-desc.xml",
                           "/IGD.xml",
                           "/ssdp/desc-DSM-eth0.xml",
                           "/ssdp/desc-DSM-eth1.xml",
                           "/ssdp/desc-DSM-bond0.xml",
                           "/etc/linuxigd/gatedesc.xml",
                           "/upnp/descr.xml",
                           "/upnp/BasicDevice.xml",
                           "/cameradesc.xml",
                           "/bmlinks/ddf.xml",
                           "/picsdesc.xml",
                           "/rss/Starter_desc.xml",
                           "/DSDeviceDescription.xml",
                           "/upnpdevicedesc.xml",
                           "/ssdp/desc-DSM-eth1.4000.xml",
                           "/ssdp/desc-DSM-ovs_eth0.xml",
                           "/upnp.jsp",
                           "/wps_device.xml",
                           "/desc/root.cs",
                           "/MediaServerDevDesc.xml",
                           "/UPnP/IGD.xml",
                           "/gatedesc.xml",
                           "/edevicedesc.xml",
                           # From this:
                           # https://cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/
                           "/IPMIdevicedesc.xml"
);

# nb: The TCP port depends on the vendor, currently the most commonly found port (Realtek) is used
# as a default
port = http_get_port( default:52881 );

# nb: If we have already found a UPnP .xml on this port there is no need to touch this again. This
# also solves the problem that if the location header only points to e.g.:
# LOCATION: http://<redacted>:80/
# without any .xml included (seen that on at least one "live" system) we're still trying to
# enumerate all known .xml files
if ( loc_port && port == loc_port )
  exit( 0 );

foreach location( xml_locations ) {

  res = http_get_cache( item:location, port:port );

  if ( res && res =~ "^HTTP/(1\.[01]|2) 200" && eregmatch( string:res, pattern:xml_verification_pattern, icase:FALSE ) ) {
    extra = handleUPnPXML( xml:res, port:port );
    set_kb_item( name:"upnp/tcp/" + port + "/location", value:location );

    report  = "The remote Host exposes an UPnP root device XML on port " + port + '/tcp.\n';
    report += '\nThe XML can be found at the location:\n  ' + http_report_vuln_url( port:port, url:location, url_only:TRUE );
    if ( ! isnull( extra ) )
      report += '\n\nExcerpt from the obtained data:\n' + extra;

    break;
  }
}

if ( report ) {
  service_register( port:port, ipproto:"tcp", proto:"upnp" );
  log_message( data:report, port:port, proto:"tcp" );
}

exit( 0 );
