# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:111");
  script_oid("1.3.6.1.4.1.25623.1.0.831701");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-26 11:15:40 +0530 (Thu, 26 Jul 2012)");
  script_cve_id("CVE-2012-1177");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2012:111");
  script_name("Mandriva Update for libgdata MDVSA-2012:111 (libgdata)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgdata'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"libgdata on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"A vulnerability has been discovered and corrected in libgdata:

  It was found that previously libgdata, a GLib-based library for
  accessing online service APIs using the GData protocol, did not
  perform SSL certificates validation even for secured connections. An
  application, linked against the libgdata library and holding the
  trust about the other side of the connection being the valid owner
  of the certificate, could be tricked into accepting of a spoofed SSL
  certificate by mistake (MITM attack) (CVE-2012-1177).

  The updated packages have been patched to correct this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"libgdata7", rpm:"libgdata7~0.6.6~3.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgdata-devel", rpm:"libgdata-devel~0.6.6~3.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgdata-i18n", rpm:"libgdata-i18n~0.6.6~3.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gdata7", rpm:"lib64gdata7~0.6.6~3.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gdata-devel", rpm:"lib64gdata-devel~0.6.6~3.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
