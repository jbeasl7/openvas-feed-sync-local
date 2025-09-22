# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-02/msg00013.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831334");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-22 06:09:45 +0100 (Tue, 22 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2011:031");
  script_cve_id("CVE-2011-0447", "CVE-2011-0696", "CVE-2011-0697", "CVE-2011-0698");
  script_name("Mandriva Update for python-django MDVSA-2011:031 (python-django)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2010\.1|2010\.0)");
  script_tag(name:"affected", value:"python-django on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in python-django:

  Django 1.1.x before 1.1.4 and 1.2.x before 1.2.5 does not properly
  validate HTTP requests that contain an X-Requested-With header,
  which makes it easier for remote attackers to conduct cross-site
  request forgery (CSRF) attacks via forged AJAX requests that leverage
  a combination of browser plugins and redirects, a related issue to
  CVE-2011-0447 (CVE-2011-0696).

  Cross-site scripting (XSS) vulnerability in Django 1.1.x before
  1.1.4 and 1.2.x before 1.2.5 might allow remote attackers to inject
  arbitrary web script or HTML via a filename associated with a file
  upload (CVE-2011-0697).

  Directory traversal vulnerability in Django 1.1.x before 1.1.4 and
  1.2.x before 1.2.5 on Windows might allow remote attackers to read or
  execute files via a / (slash) character in a key in a session cookie,
  related to session replays (CVE-2011-0698).

  The updated packages have been upgraded to the 1.1.4 version which
  is not vulnerable to these issues.");
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

  if ((res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.1.4~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.1.4~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
