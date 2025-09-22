# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871690");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-11-04 05:41:50 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2016-5419", "CVE-2016-5420", "CVE-2016-7141");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for curl RHSA-2016:2575-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The curl packages provide the libcurl
library and the curl utility for downloading files from servers using various
protocols, including HTTP, FTP, and LDAP.

Security Fix(es):

  * It was found that the libcurl library did not prevent TLS session
resumption when the client certificate had changed. An attacker could
potentially use this flaw to hijack the authentication of the connection by
leveraging a previously created connection with a different client
certificate. (CVE-2016-5419)

  * It was found that the libcurl library did not check the client
certificate when choosing the TLS connection to reuse. An attacker could
potentially use this flaw to hijack the authentication of the connection by
leveraging a previously created connection with a different client
certificate. (CVE-2016-5420)

  * It was found that the libcurl library using the NSS (Network Security
Services) library as TLS/SSL backend incorrectly re-used client
certificates for subsequent TLS connections in certain cases. An attacker
could potentially use this flaw to hijack the authentication of the
connection by leveraging a previously created connection with a different
client certificate. (CVE-2016-7141)

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section.");
  script_tag(name:"affected", value:"curl on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:2575-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-November/msg00011.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~35.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.29.0~35.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~35.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~35.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
