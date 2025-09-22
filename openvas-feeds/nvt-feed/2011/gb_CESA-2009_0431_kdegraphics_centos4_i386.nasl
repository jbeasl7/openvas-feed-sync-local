# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015921.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880934");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0431");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0799",
                "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181",
                "CVE-2009-1182", "CVE-2009-1183");
  script_name("CentOS Update for kdegraphics CESA-2009:0431 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdegraphics'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"kdegraphics on CentOS 4");
  script_tag(name:"insight", value:"The kdegraphics packages contain applications for the K Desktop
  Environment, including KPDF, a viewer for Portable Document Format (PDF)
  files.

  Multiple integer overflow flaws were found in KPDF's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause KPDF to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0147,
  CVE-2009-1179)

  Multiple buffer overflow flaws were found in KPDF's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause KPDF to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0146,
  CVE-2009-1182)

  Multiple flaws were found in KPDF's JBIG2 decoder that could lead to the
  freeing of arbitrary memory. An attacker could create a malicious PDF file
  that would cause KPDF to crash or, potentially, execute arbitrary code when
  opened. (CVE-2009-0166, CVE-2009-1180)

  Multiple input validation flaws were found in KPDF's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause KPDF to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0800)

  Multiple denial of service flaws were found in KPDF's JBIG2 decoder. An
  attacker could create a malicious PDF that would cause KPDF to crash when
  opened. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

  Red Hat would like to thank Braden Thomas and Drew Yao of the Apple Product
  Security team, and Will Dormann of the CERT/CC for responsibly reporting
  these flaws.

  Users are advised to upgrade to these updated packages, which contain
  backported patches to resolve these issues.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.3.1~13.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-devel", rpm:"kdegraphics-devel~3.3.1~13.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
