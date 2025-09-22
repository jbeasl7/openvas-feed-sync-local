# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-August/016074.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880794");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:04:10 +0000 (Fri, 02 Feb 2024)");
  script_xref(name:"CESA", value:"2009:1206");
  script_cve_id("CVE-2009-2414", "CVE-2009-2416");
  script_name("CentOS Update for libxml2 CESA-2009:1206 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libxml2 on CentOS 5");
  script_tag(name:"insight", value:"libxml is a library for parsing and manipulating XML files. A Document Type
  Definition (DTD) defines the legal syntax (and also which elements can be
  used) for certain types of files, such as XML files.

  A stack overflow flaw was found in the way libxml processes the root XML
  document element definition in a DTD. A remote attacker could provide a
  specially-crafted XML file, which once opened by a local, unsuspecting
  user, would lead to denial of service (application crash). (CVE-2009-2414)

  Multiple use-after-free flaws were found in the way libxml parses the
  Notation and Enumeration attribute types. A remote attacker could provide
  a specially-crafted XML file, which once opened by a local, unsuspecting
  user, would lead to denial of service (application crash). (CVE-2009-2416)

  Users should upgrade to these updated packages, which contain backported
  patches to resolve these issues. For Red Hat Enterprise Linux 3, they
  contain backported patches for the libxml and libxml2 packages. For Red Hat
  Enterprise Linux 4 and 5, they contain backported patches for the libxml2
  packages. The desktop must be restarted (log out, then log back in) for
  this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.26~2.1.2.8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.26~2.1.2.8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.26~2.1.2.8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
