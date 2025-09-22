# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52214");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1009", "CVE-2004-1090", "CVE-2004-1091", "CVE-2004-1092", "CVE-2004-1093");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: mc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/2b2b333b-6bd3-11d9-95f8-000a95bc6fae.html");
  script_tag(name:"insight", value:"The following package is affected: mc

CVE-2004-1004
Multiple format string vulnerabilities in Midnight Commander (mc)
4.5.55 and earlier allow remote attackers to have an unknown impact.

CVE-2004-1005
Multiple buffer overflows in Midnight Commander (mc) 4.5.55 and
earlier allow remote attackers to have an unknown impact.

CVE-2004-1009
Midnight commander (mc) 4.5.55 and earlier allows remote attackers to
cause a denial of service (infinite loop) via unknown attack vectors.

CVE-2004-1090
Midnight commander (mc) 4.5.55 and earlier allows remote attackers to
cause a denial of service via 'a corrupt section header.'

CVE-2004-1091
Midnight commander (mc) 4.5.55 and earlier allows remote attackers to
cause a denial of service by triggering a null dereference.

CVE-2004-1092
Midnight commander (mc) 4.5.55 and earlier allows remote attackers to
cause a denial of service by causing mc to free unallocated memory.

CVE-2004-1093
Midnight commander (mc) 4.5.55 and earlier allows remote attackers to
cause a denial of service via 'use of already freed memory.'");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"mc");
if(!isnull(bver) && revcomp(a:bver, b:"4.6.0")<0) {
  txt += 'Package mc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
