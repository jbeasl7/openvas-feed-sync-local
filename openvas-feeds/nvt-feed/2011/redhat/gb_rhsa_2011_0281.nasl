# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-February/msg00024.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870394");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-02-18 15:15:05 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:0281-01");
  script_cve_id("CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4472", "CVE-2010-4471");
  script_name("RedHat Update for java-1.6.0-openjdk RHSA-2011:0281-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit.

  A flaw was found in the Swing library. Forged TimerEvents could be used to
  bypass SecurityManager checks, allowing access to otherwise blocked files
  and directories. (CVE-2010-4465)

  A flaw was found in the HotSpot component in OpenJDK. Certain bytecode
  instructions confused the memory management within the Java Virtual Machine
  (JVM), which could lead to heap corruption. (CVE-2010-4469)

  A flaw was found in the way JAXP (Java API for XML Processing) components
  were handled, allowing them to be manipulated by untrusted applets. This
  could be used to elevate privileges and bypass secure XML processing
  restrictions. (CVE-2010-4470)

  It was found that untrusted applets could create and place cache entries in
  the name resolution cache. This could allow an attacker targeted
  manipulation over name resolution until the OpenJDK VM is restarted.
  (CVE-2010-4448)

  It was found that the Java launcher provided by OpenJDK did not check the
  LD_LIBRARY_PATH environment variable for insecure empty path elements. A
  local attacker able to trick a user into running the Java launcher while
  working from an attacker-writable directory could use this flaw to load an
  untrusted library, subverting the Java security model. (CVE-2010-4450)

  A flaw was found in the XML Digital Signature component in OpenJDK.
  Untrusted code could use this flaw to replace the Java Runtime Environment
  (JRE) XML Digital Signature Transform or C14N algorithm implementations to
  intercept digital signature operations. (CVE-2010-4472)

  Note: All of the above flaws can only be remotely triggered in OpenJDK by
  calling the 'appletviewer' application.

  This update also provides one defense in depth patch. (BZ#676019)

  All users of java-1.6.0-openjdk are advised to upgrade to these updated
  packages, which resolve these issues. All running instances of OpenJDK Java
  must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.20.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~1.20.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.20.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.20.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.20.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.20.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
