# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69998");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2364",
                "CVE-2011-2365", "CVE-2011-2373", "CVE-2011-2377", "CVE-2011-2371",
                "CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2363", "CVE-2011-2362",
                "CVE-2011-2366", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2369",
                "CVE-2011-2370");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox
   linux-firefox
   thunderbird
   linux-thunderbird");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-19.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-20.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-21.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-22.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-23.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-24.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-25.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-26.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-27.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-28.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/dfe40cff-9c3f-11e0-9bec-6c626dd55a41.html");

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

bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"3.5.*,1")>0 && revcomp(a:bver, b:"3.5.20,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.6.*,1")>0 && revcomp(a:bver, b:"3.6.18,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"4.0.*,1")>0 && revcomp(a:bver, b:"5.0,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.18,1")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.11")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"3.1.11")<0) {
  txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}