# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-February/019254.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881602");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-22 10:04:08 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2013-0169", "CVE-2013-1484", "CVE-2013-1485", "CVE-2013-1486");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2013:0275");
  script_name("CentOS Update for java CESA-2013:0275 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 7 Java Runtime Environment and the
  OpenJDK 7 Software Development Kit.

  Multiple improper permission check issues were discovered in the JMX and
  Libraries components in OpenJDK. An untrusted Java application or applet
  could use these flaws to bypass Java sandbox restrictions. (CVE-2013-1486,
  CVE-2013-1484)

  An improper permission check issue was discovered in the Libraries
  component in OpenJDK. An untrusted Java application or applet could use
  this flaw to bypass certain Java sandbox restrictions. (CVE-2013-1485)

  It was discovered that OpenJDK leaked timing information when decrypting
  TLS/SSL protocol encrypted records when CBC-mode cipher suites were used.
  A remote attacker could possibly use this flaw to retrieve plain text from
  the encrypted packets by using a TLS/SSL server as a padding oracle.
  (CVE-2013-0169)

  This erratum also upgrades the OpenJDK package to IcedTea7 2.3.7. Refer to
  the NEWS file, linked to in the References, for further information.

  All users of java-1.7.0-openjdk are advised to upgrade to these updated
  packages, which resolve these issues. All running instances of OpenJDK Java
  must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.9~2.3.7.1.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.9~2.3.7.1.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.9~2.3.7.1.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.9~2.3.7.1.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.9~2.3.7.1.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
