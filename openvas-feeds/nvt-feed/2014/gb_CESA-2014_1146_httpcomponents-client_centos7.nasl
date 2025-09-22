# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882002");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-10 06:19:32 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-3577", "CVE-2012-6153");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("CentOS Update for httpcomponents-client CESA-2014:1146 centos7");
  script_tag(name:"insight", value:"HttpClient is an HTTP/1.1 compliant HTTP
agent implementation based on httpcomponents HttpCore.

It was discovered that the HttpClient incorrectly extracted host name from
an X.509 certificate subject's Common Name (CN) field. A man-in-the-middle
attacker could use this flaw to spoof an SSL server using a specially
crafted X.509 certificate. (CVE-2014-3577)

For additional information on this flaw, refer to the Knowledgebase
article in the References section.

All httpcomponents-client users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to use the
Red Hat Network to apply this update are available at the linked references.

5. Bugs fixed:

1129074 - CVE-2014-3577 Apache HttpComponents client: SSL hostname verification
bypass, incomplete CVE-2012-6153 fix

6. Package List:

Red Hat Enterprise Linux Client Optional (v. 7):

Source:
httpcomponents-client-4.2.5-5.el7_0.src.rpm

noarch:
httpcomponents-client-4.2.5-5.el7_0.noarch.rpm
httpcomponents-client-javadoc-4.2.5-5.el7_0.noarch.rpm

Red Hat Enterprise Linux ComputeNode Optional (v. 7):

Source:
httpcomponents-client-4.2.5-5.el7_0.src.rpm

noarch:
httpcomponents-client-4.2.5-5.el7_0.noarch.rpm
httpcomponents-client-javadoc-4.2.5-5.el7_0.noarch.rpm

Red Hat Enterprise Linux Server (v. 7):

Source:
httpcomponents-client-4.2.5-5.el7_0.src.rpm

noarch:
httpcomponents-client-4.2.5-5.el7_0.noarch.rpm

Red Hat Enterprise Linux Server Optional (v. 7):

Source:
httpcomponents-client-4.2.5-5.el7_0.src.rpm

noarch:
httpcomponents-client-4.2.5-5.el7_0.noarch.rpm
httpcomponents-client-javadoc-4.2.5-5.el7_0.noarch.rpm

Red Hat Enterprise Linux Workstation (v. 7):

Source:
httpcomponents-client-4.2.5-5.el7_0.src.rpm

noarch:
httpcomponents-client-4.2.5-5.el7_0.noarch.rpm

Red Hat Enterprise Linux Workstation Optional (v. 7):

noarch:
httpcomponents-client-javadoc-4.2.5-5.el7_0.noarch.rpm

These packages are GPG signed by Red Hat for security. Our key and
details on how to verify the signature are available from the references.

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"httpcomponents-client on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1146");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-September/020530.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/team/key/#package");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpcomponents-client'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"httpcomponents-client", rpm:"httpcomponents-client~4.2.5~5.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpcomponents-client-javadoc", rpm:"httpcomponents-client-javadoc~4.2.5~5.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
