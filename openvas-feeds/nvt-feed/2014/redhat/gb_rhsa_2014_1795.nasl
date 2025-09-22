# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871284");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-11-04 06:12:03 +0100 (Tue, 04 Nov 2014)");
  script_cve_id("CVE-2014-4337", "CVE-2014-4338");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for cups-filters RHSA-2014:1795-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-filters'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The cups-filters package contains backends, filters, and other software
that was once part of the core CUPS distribution but is now maintained
independently.

An out-of-bounds read flaw was found in the way the process_browse_data()
function of cups-browsed handled certain browse packets. A remote attacker
could send a specially crafted browse packet that, when processed by
cups-browsed, would crash the cups-browsed daemon. (CVE-2014-4337)

A flaw was found in the way the cups-browsed daemon interpreted the
'BrowseAllow' directive in the cups-browsed.conf file. An attacker able to
add a malformed 'BrowseAllow' directive to the cups-browsed.conf file could
use this flaw to bypass intended access restrictions. (CVE-2014-4338)

All cups-filters users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After installing
this update, the cups-browsed daemon will be restarted automatically.");
  script_tag(name:"affected", value:"cups-filters on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:1795-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-November/msg00010.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.0.35~15.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-filters-debuginfo", rpm:"cups-filters-debuginfo~1.0.35~15.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-filters-libs", rpm:"cups-filters-libs~1.0.35~15.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}