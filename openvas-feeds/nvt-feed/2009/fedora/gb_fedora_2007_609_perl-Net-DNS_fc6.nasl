# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-July/msg00044.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861344");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name:"FEDORA", value:"2007-609");
  script_name("Fedora Update for perl-Net-DNS FEDORA-2007-609");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Net-DNS'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms", re:"ssh/login/release=FC6");

  script_tag(name:"affected", value:"perl-Net-DNS on Fedora Core 6");

  script_tag(name:"solution", value:"Please install the updated package(s).");
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

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"perl-Net-DNS", rpm:"perl-Net-DNS~0.60~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/perl-Net-DNS-debuginfo", rpm:"x86_64/debug/perl-Net-DNS-debuginfo~0.60~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/perl-Net-DNS", rpm:"x86_64/perl-Net-DNS~0.60~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/perl-Net-DNS", rpm:"i386/perl-Net-DNS~0.60~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/perl-Net-DNS-debuginfo", rpm:"i386/debug/perl-Net-DNS-debuginfo~0.60~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
