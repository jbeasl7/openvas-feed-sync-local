# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-August/016868.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880591");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:34:14 +0000 (Fri, 02 Feb 2024)");
  script_xref(name:"CESA", value:"2010:0603");
  script_cve_id("CVE-2010-2547");
  script_name("CentOS Update for gnupg2 CESA-2010:0603 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gnupg2 on CentOS 5");
  script_tag(name:"insight", value:"The GNU Privacy Guard (GnuPG or GPG) is a tool for encrypting data and
  creating digital signatures, compliant with the proposed OpenPGP Internet
  standard and the S/MIME standard.

  A use-after-free flaw was found in the way gpgsm, a Cryptographic Message
  Syntax (CMS) encryption and signing tool, handled X.509 certificates with
  a large number of Subject Alternate Names. A specially-crafted X.509
  certificate could, when imported, cause gpgsm to crash or, possibly,
  execute arbitrary code. (CVE-2010-2547)

  All gnupg2 users should upgrade to this updated package, which contains a
  backported patch to correct this issue.");
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

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.10~3.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
