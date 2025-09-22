# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-05/msg00009.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831392");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-17 15:58:48 +0200 (Tue, 17 May 2011)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_xref(name:"MDVSA", value:"2011:087");
  script_cve_id("CVE-2011-0904", "CVE-2011-0905");
  script_name("Mandriva Update for vino MDVSA-2011:087 (vino)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vino'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2010\.1");
  script_tag(name:"affected", value:"vino on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in vino:

  The rfbSendFramebufferUpdate function in
  server/libvncserver/rfbserver.c in vino-server in Vino 2.x before
  2.28.3, 2.32.x before 2.32.2, 3.0.x before 3.0.2, and 3.1.x before
  3.1.1, when raw encoding is used, allows remote authenticated users to
  cause a denial of service (daemon crash) via a large (1) X position or
  (2) Y position value in a framebuffer update request that triggers
  an out-of-bounds memory access, related to the rfbTranslateNone and
  rfbSendRectEncodingRaw functions (CVE-2011-0904).

  The rfbSendFramebufferUpdate function in
  server/libvncserver/rfbserver.c in vino-server in Vino 2.x before
  2.28.3, 2.32.x before 2.32.2, 3.0.x before 3.0.2, and 3.1.x before
  3.1.1, when tight encoding is used, allows remote authenticated users
  to cause a denial of service (daemon crash) via crafted dimensions
  in a framebuffer update request that triggers an out-of-bounds read
  operation (CVE-2011-0905).

  The updated packages have been upgraded to 2.28.3 which is not
  vulnerable to these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"vino", rpm:"vino~2.28.3~1.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
