# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114685");
  script_version("2024-07-05T15:38:46+0000");
  script_cve_id("CVE-2024-38526", "CVE-2024-38537");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-05 15:38:46 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-03 08:37:52 +0000 (Wed, 03 Jul 2024)");
  script_name("Web Application using Malicious polyfill.io CDN (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Malware");
  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/webapp_using_polyfill/detected");

  script_xref(name:"URL", value:"https://sansec.io/research/polyfill-supply-chain-attack");
  script_xref(name:"URL", value:"https://blog.cloudflare.com/polyfill-io-now-available-on-cdnjs-reduce-your-supply-chain-risk");
  script_xref(name:"URL", value:"https://web.archive.org/web/20240624110153/https://github.com/polyfillpolyfill/polyfill-service/issues/2873");
  script_xref(name:"URL", value:"https://web.archive.org/web/20240229113710/https://github.com/polyfillpolyfill/polyfill-service/issues/2834");
  script_xref(name:"URL", value:"https://x.com/nullifysecurity/status/1806489013567778923");
  script_xref(name:"URL", value:"https://censys.com/july-2-polyfill-io-supply-chain-attack-digging-into-the-web-of-compromised-domains/");

  script_tag(name:"summary", value:"This script reports if a web page of the remote host is
  integrating JavaScript (.js) files hosted on the malicious polyfill.io CDN (or any affiliated
  domain provided by the same new owner).");

  script_tag(name:"insight", value:"- In June 2024 it was determined that the new owner of the
  popular Polyfill JS project injects malware into more than 100k sites embedding JavaScript from
  this CDN

  - The same owner has been observed since at least June 2023 to spread malware via additional
  domains (checked by this script) as well

  Note: The following products are known to use the malicious domain by default and thus the
  relevant CVEs have been added to this script:

  - CVE-2024-38526: pdoc

  - CVE-2024-38537: Fides");

  script_tag(name:"impact", value:"Malicious payloads are shipped in the form of malware to users
  of the affected web page which allows multiple attack vectors like a redirect of the user to
  phising sites or similar.");

  script_tag(name:"solution", value:"Replace the malicious JavaScript reference with a trustworthy
  alternative. Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

webappList = get_kb_list( "www/" + host + "/" + port + "/content/webapp_using_polyfill" );
if( ! webappList || ! is_array( webappList ) )
  exit( 99 );

# nb: Sort to not report changes on delta reports if just the order is different
webappList = sort( webappList );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach webappItem( webappList ) {

  info = split( webappItem, sep:"#----#", keep:FALSE );
  if( ! info || max_index( info ) != 2 )
    continue; # nb: something went wrong...

  webPage = info[0];
  webCode = info[1];

  if( report )
    report += '\n\n';

  report += "URL/page on the target:   " + webPage + '\n';
  report += "Embedded JavaScript code: " + webCode;
}

security_message( port:port, data:'The following JavaScript code has been identified pointing to (a) malicious domain(s):\n\n' + report );
exit( 0 );
