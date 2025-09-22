# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-May/msg00066.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861490");
  script_version("2023-07-04T05:05:35+0000");
  script_tag(name:"last_modification", value:"2023-07-04 05:05:35 +0000 (Tue, 04 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2007-552");
  script_cve_id("CVE-2007-2867", "CVE-2007-2868", "CVE-2007-1562", "CVE-2007-1362", "CVE-2007-2869", "CVE-2007-1558", "CVE-2007-2870", "CVE-2007-2871");
  script_name("Fedora Update for seamonkey FEDORA-2007-552");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms", re:"ssh/login/release=FC5");

  script_tag(name:"affected", value:"seamonkey on Fedora Core 5");
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

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/seamonkey-dom-inspector", rpm:"x86_64/seamonkey-dom-inspector~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/seamonkey-devel", rpm:"x86_64/seamonkey-devel~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/seamonkey-js-debugger", rpm:"x86_64/seamonkey-js-debugger~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/seamonkey", rpm:"x86_64/seamonkey~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/seamonkey-chat", rpm:"x86_64/seamonkey-chat~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/seamonkey-mail", rpm:"x86_64/seamonkey-mail~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/seamonkey-debuginfo", rpm:"x86_64/debug/seamonkey-debuginfo~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/seamonkey-devel", rpm:"i386/seamonkey-devel~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/seamonkey-dom-inspector", rpm:"i386/seamonkey-dom-inspector~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/seamonkey-debuginfo", rpm:"i386/debug/seamonkey-debuginfo~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/seamonkey-js-debugger", rpm:"i386/seamonkey-js-debugger~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/seamonkey-mail", rpm:"i386/seamonkey-mail~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/seamonkey", rpm:"i386/seamonkey~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/seamonkey-chat", rpm:"i386/seamonkey-chat~1.0.9~1.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}