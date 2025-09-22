# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:143");
  script_oid("1.3.6.1.4.1.25623.1.0.831728");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-24 09:57:26 +0530 (Fri, 24 Aug 2012)");
  script_cve_id("CVE-2012-3442", "CVE-2012-3443", "CVE-2012-3444");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"MDVSA", value:"2012:143");
  script_name("Mandriva Update for python-django MDVSA-2012:143 (python-django)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2011\.0|mes5\.2)");
  script_tag(name:"affected", value:"python-django on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in
  python-django:

  The (1) django.http.HttpResponseRedirect and (2)
  django.http.HttpResponsePermanentRedirect classes in Django before
  1.3.2 and 1.4.x before 1.4.1 do not validate the scheme of a redirect
  target, which might allow remote attackers to conduct cross-site
  scripting (XSS) attacks via a data: URL (CVE-2012-3442).

  The django.forms.ImageField class in the form system in Django
  before 1.3.2 and 1.4.x before 1.4.1 completely decompresses image
  data during image validation, which allows remote attackers to cause
  a denial of service (memory consumption) by uploading an image file
  (CVE-2012-3443).

  The get_image_dimensions function in the image-handling functionality
  in Django before 1.3.2 and 1.4.x before 1.4.1 uses a constant chunk
  size in all attempts to determine dimensions, which allows remote
  attackers to cause a denial of service (process or thread consumption)
  via a large TIFF image (CVE-2012-3444).

  The updated packages have been upgraded to the 1.3.3 version which
  is not vulnerable to these issues.");
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

  if ((res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.3.3~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.3.3~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
