# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71283");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
  script_name("FreeBSD Ports: freetype2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: freetype2

CVE-2012-1126
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted property data in a BDF
font.
CVE-2012-1127
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted glyph or bitmap data in a
BDF font.
CVE-2012-1128
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (NULL pointer dereference and memory corruption) or possibly
execute arbitrary code via a crafted TrueType font.
CVE-2012-1129
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted SFNT string in a Type 42
font.
CVE-2012-1130
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted property data in a PCF
font.

Text truncated. Please see the references for more information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/freetype/files/freetype2/2.4.9/README/view");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=806270");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/462e2d6c-8017-11e1-a571-bcaec565249c.html");

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

bver = portver(pkg:"freetype2");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.9")<0) {
  txt += "Package freetype2 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}