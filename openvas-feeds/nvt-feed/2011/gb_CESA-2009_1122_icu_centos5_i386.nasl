# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-June/016003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880837");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"CESA", value:"2009:1122");
  script_cve_id("CVE-2009-0153");
  script_name("CentOS Update for icu CESA-2009:1122 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"icu on CentOS 5");
  script_tag(name:"insight", value:"The International Components for Unicode (ICU) library provides robust and
  full-featured Unicode services.

  A flaw was found in the way ICU processed certain, invalid byte sequences
  during Unicode conversion. If an application used ICU to decode malformed,
  multibyte character data, it may have been possible to bypass certain
  content protection mechanisms, or display information in a manner
  misleading to the user. (CVE-2009-0153)

  All users of icu should upgrade to these updated packages, which contain
  backported patches to resolve this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"icu", rpm:"icu~3.6~5.11.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libicu", rpm:"libicu~3.6~5.11.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libicu-devel", rpm:"libicu-devel~3.6~5.11.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~3.6~5.11.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
