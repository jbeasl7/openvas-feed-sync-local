# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61185");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2007-6420", "CVE-2008-2364");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: apache");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: apache

CVE-2007-6420
Cross-site request forgery (CSRF) vulnerability in the
balancer-manager in mod_proxy_balancer for Apache HTTP Server 2.2.x
allows remote attackers to gain privileges via unpsecified vectors.
CVE-2008-2364
The ap_proxy_http_process_response function in mod_proxy_http.c in the
mod_proxy module in the Apache HTTP Server 2.0.63 and 2.2.8 does not
limit the number of forwarded interim responses, which allows remote
HTTP servers to cause a denial of service (memory consumption) via a
large number of interim responses.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/c84dc9ad-41f7-11dd-a4f9-00163e000016.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.0")>0 && revcomp(a:bver, b:"2.2.9")<0) {
  txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}