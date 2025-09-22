# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-November/msg00310.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861064");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2007-2985");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_name("Fedora Update for kde-i18n FEDORA-2007-2985");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kde-i18n'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC7");
  script_tag(name:"affected", value:"kde-i18n on Fedora 7");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"kde-i18n", rpm:"kde-i18n~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Slovak", rpm:"kde-i18n-Slovak~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-German", rpm:"kde-i18n-German~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Portuguese", rpm:"kde-i18n-Portuguese~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Tamil", rpm:"kde-i18n-Tamil~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Icelandic", rpm:"kde-i18n-Icelandic~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Finnish", rpm:"kde-i18n-Finnish~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Norwegian", rpm:"kde-i18n-Norwegian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Italian", rpm:"kde-i18n-Italian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Bulgarian", rpm:"kde-i18n-Bulgarian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Chinese-Big5", rpm:"kde-i18n-Chinese-Big5~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Polish", rpm:"kde-i18n-Polish~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Lithuanian", rpm:"kde-i18n-Lithuanian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Romanian", rpm:"kde-i18n-Romanian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Brazil", rpm:"kde-i18n-Brazil~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Czech", rpm:"kde-i18n-Czech~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Danish", rpm:"kde-i18n-Danish~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Norwegian-Nynorsk", rpm:"kde-i18n-Norwegian-Nynorsk~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Punjabi", rpm:"kde-i18n-Punjabi~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Hindi", rpm:"kde-i18n-Hindi~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Catalan", rpm:"kde-i18n-Catalan~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-British", rpm:"kde-i18n-British~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Ukrainian", rpm:"kde-i18n-Ukrainian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Spanish", rpm:"kde-i18n-Spanish~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Bengali", rpm:"kde-i18n-Bengali~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Hebrew", rpm:"kde-i18n-Hebrew~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Arabic", rpm:"kde-i18n-Arabic~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Chinese", rpm:"kde-i18n-Chinese~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Korean", rpm:"kde-i18n-Korean~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Dutch", rpm:"kde-i18n-Dutch~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Serbian", rpm:"kde-i18n-Serbian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Hungarian", rpm:"kde-i18n-Hungarian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Japanese", rpm:"kde-i18n-Japanese~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Estonian", rpm:"kde-i18n-Estonian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Russian", rpm:"kde-i18n-Russian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-French", rpm:"kde-i18n-French~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Swedish", rpm:"kde-i18n-Swedish~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Greek", rpm:"kde-i18n-Greek~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Slovenian", rpm:"kde-i18n-Slovenian~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kde-i18n-Turkish", rpm:"kde-i18n-Turkish~3.5.8~1.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}