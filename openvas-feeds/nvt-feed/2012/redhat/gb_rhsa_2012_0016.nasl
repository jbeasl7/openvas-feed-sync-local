# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-January/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870530");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-01-13 10:45:41 +0530 (Fri, 13 Jan 2012)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:0016-01");
  script_cve_id("CVE-2011-0216", "CVE-2011-2834", "CVE-2011-3905", "CVE-2011-3919");
  script_name("RedHat Update for libxml2 RHSA-2012:0016-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"affected", value:"libxml2 on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The libxml2 library is a development toolbox providing the implementation
  of various XML standards. One of those standards is the XML Path Language
  (XPath), which is a language for addressing parts of an XML document.

  A heap-based buffer overflow flaw was found in the way libxml2 decoded
  entity references with long names. A remote attacker could provide a
  specially-crafted XML file that, when opened in an application linked
  against libxml2, would cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-3919)

  An off-by-one error, leading to a heap-based buffer overflow, was found in
  the way libxml2 parsed certain XML files. A remote attacker could provide a
  specially-crafted XML file that, when opened in an application linked
  against libxml2, would cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-0216)

  A flaw was found in the way libxml2 parsed certain XPath expressions. If an
  attacker were able to supply a specially-crafted XML file to an application
  using libxml2, as well as an XPath expression for that application to run
  against the crafted file, it could cause the application to crash.
  (CVE-2011-2834)

  Note: Red Hat does not ship any applications that use libxml2 in a way that
  would allow the CVE-2011-2834 flaw to be exploited. However, third-party
  applications may allow XPath expressions to be passed which could trigger
  this flaw.

  An out-of-bounds memory read flaw was found in libxml2. A remote attacker
  could provide a specially-crafted XML file that, when opened in an
  application linked against libxml2, would cause the application to crash.
  (CVE-2011-3905)

  All users of libxml2 are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. The desktop must
  be restarted (log out, then log back in) for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.16~12.9", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-debuginfo", rpm:"libxml2-debuginfo~2.6.16~12.9", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.16~12.9", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.16~12.9", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
