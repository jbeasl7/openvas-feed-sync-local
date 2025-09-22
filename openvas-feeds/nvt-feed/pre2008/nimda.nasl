# SPDX-FileCopyrightText: 2001 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10767");
  script_version("2023-08-03T05:05:16+0000");
  script_cve_id("CVE-2001-0545", "CVE-2001-0508", "CVE-2001-0544", "CVE-2001-0506", "CVE-2001-0507");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Tests for Nimda Worm infected HTML files");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Matt Moore");
  script_family("Malware");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-044");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2001-26.html");

  script_tag(name:"solution", value:"Take this server offline immediately, rebuild it and
  apply ALL vendor patches and security updates before reconnecting server to the internet,
  as well as security settings discussed in

  Additional Information section of Microsoft's web site linked in the references.

  Check ALL of your local Microsoft based workstations for infection.");

  script_tag(name:"summary", value:"Your server appears to have been compromised by the
  Nimda mass mailing worm. It uses various known IIS vulnerabilities to compromise the
  server.");

  script_tag(name:"insight", value:"Anyone visiting compromised Web servers will be prompted to
  download an .eml (Outlook Express) email file, which contains the worm as an attachment.

  Also, the worm will create open network shares on the infected
  computer, allowing access to the system. During this process
  the worm creates the guest account with Administrator privileges.

  Note: this worm has already infected more than 500.000 computers
  worldwide since its release in late 2001.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
r = http_get_cache(item:"/", port:port);
if(r && "readme.eml" >< r) {
  security_message(port:port);
  exit(0);
}

exit(99);
