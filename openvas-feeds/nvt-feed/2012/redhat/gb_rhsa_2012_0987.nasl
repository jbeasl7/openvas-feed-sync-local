# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00039.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870771");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:20 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2012-2328");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2012:0987-04");
  script_name("RedHat Update for sblim-cim-client2 RHSA-2012:0987-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sblim-cim-client2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"sblim-cim-client2 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The SBLIM (Standards-Based Linux Instrumentation for Manageability) CIM
  (Common Information Model) Client is a class library for Java applications
  that provides access to CIM servers using the CIM Operations over HTTP
  protocol defined by the DMTF (Distributed Management Task Force) standards.

  It was found that the Java HashMap implementation was susceptible to
  predictable hash collisions. SBLIM uses HashMap when parsing XML inputs. A
  specially-crafted CIM-XML message from a WBEM (Web-Based Enterprise
  Management) server could cause a SBLIM client to use an excessive amount of
  CPU. Randomization has been added to help avoid collisions. (CVE-2012-2328)

  All users of sblim-cim-client2 are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"sblim-cim-client2", rpm:"sblim-cim-client2~2.1.3~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
