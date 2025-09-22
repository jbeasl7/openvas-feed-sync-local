# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2011-October/068042.html");
  script_oid("1.3.6.1.4.1.25623.1.0.863579");
  script_version("2023-06-30T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-30 16:09:17 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"FEDORA", value:"2011-13860");
  script_cve_id("CVE-2011-3208");
  script_name("Fedora Update for cyrus-imapd FEDORA-2011-13860");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-imapd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC15");
  script_tag(name:"affected", value:"cyrus-imapd on Fedora 15");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.4.12~1.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
