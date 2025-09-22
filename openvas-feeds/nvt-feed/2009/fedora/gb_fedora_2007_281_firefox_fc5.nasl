# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-February/msg00146.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861440");
  script_cve_id("CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0800", "CVE-2007-0775", "CVE-2007-0995",
                "CVE-2007-0778", "CVE-2007-0780", "CVE-2007-0008", "CVE-2007-0779", "CVE-2006-6077");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2007-281");
  script_name("Fedora Update for firefox FEDORA-2007-281");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms", re:"ssh/login/release=FC5");

  script_tag(name:"affected", value:"firefox on Fedora Core 5");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~1.5.0.10~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/firefox", rpm:"x86_64/firefox~1.5.0.10~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/firefox-debuginfo", rpm:"x86_64/debug/firefox-debuginfo~1.5.0.10~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/firefox", rpm:"i386/firefox~1.5.0.10~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/firefox-debuginfo", rpm:"i386/debug/firefox-debuginfo~1.5.0.10~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
