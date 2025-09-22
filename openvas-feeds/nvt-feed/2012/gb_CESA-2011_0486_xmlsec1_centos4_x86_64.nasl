# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017509.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881415");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:49:35 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1425");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:0486");
  script_name("CentOS Update for xmlsec1 CESA-2011:0486 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmlsec1'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"xmlsec1 on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The XML Security Library is a C library based on libxml2 and OpenSSL that
  implements the XML Digital Signature and XML Encryption standards.

  A flaw was found in the way xmlsec1 handled XML files that contain an XSLT
  transformation specification. A specially-crafted XML file could cause
  xmlsec1 to create or overwrite an arbitrary file while performing the
  verification of a file's digital signature. (CVE-2011-1425)

  Red Hat would like to thank Nicolas Grgoire and Aleksey Sanin for
  reporting this issue.

  This update also fixes the following bug:

  * xmlsec1 previously used an incorrect search path when searching for
  crypto plug-in libraries, possibly trying to access such libraries using a
  relative path. (BZ#558480, BZ#700467)

  Users of xmlsec1 should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the update,
  all running applications that use the xmlsec1 library must be restarted for
  the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.6~3.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmlsec1-devel", rpm:"xmlsec1-devel~1.2.6~3.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmlsec1-openssl", rpm:"xmlsec1-openssl~1.2.6~3.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmlsec1-openssl-devel", rpm:"xmlsec1-openssl-devel~1.2.6~3.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
