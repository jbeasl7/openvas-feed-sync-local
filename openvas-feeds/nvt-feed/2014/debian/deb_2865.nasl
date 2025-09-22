# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702865");
  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067", "CVE-2014-2669");
  script_tag(name:"creation_date", value:"2014-02-19 23:00:00 +0000 (Wed, 19 Feb 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2865-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2865-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2865-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2865");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.1' package(s) announced via the DSA-2865-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various vulnerabilities were discovered in PostgreSQL:

CVE-2014-0060 Shore up GRANT ... WITH ADMIN OPTION restrictions (Noah Misch) Granting a role without ADMIN OPTION is supposed to prevent the grantee from adding or removing members from the granted role, but this restriction was easily bypassed by doing SET ROLE first. The security impact is mostly that a role member can revoke the access of others, contrary to the wishes of his grantor. Unapproved role member additions are a lesser concern, since an uncooperative role member could provide most of his rights to others anyway by creating views or SECURITY DEFINER functions.

CVE-2014-0061 Prevent privilege escalation via manual calls to PL validator functions (Andres Freund) The primary role of PL validator functions is to be called implicitly during CREATE FUNCTION, but they are also normal SQL functions that a user can call explicitly. Calling a validator on a function actually written in some other language was not checked for and could be exploited for privilege-escalation purposes. The fix involves adding a call to a privilege-checking function in each validator function. Non-core procedural languages will also need to make this change to their own validator functions, if any.

CVE-2014-0062 Avoid multiple name lookups during table and index DDL (Robert Haas, Andres Freund) If the name lookups come to different conclusions due to concurrent activity, we might perform some parts of the DDL on a different table than other parts. At least in the case of CREATE INDEX, this can be used to cause the permissions checks to be performed against a different table than the index creation, allowing for a privilege escalation attack.

CVE-2014-0063 Prevent buffer overrun with long datetime strings (Noah Misch) The MAXDATELEN constant was too small for the longest possible value of type interval, allowing a buffer overrun in interval_out(). Although the datetime input functions were more careful about avoiding buffer overrun, the limit was short enough to cause them to reject some valid inputs, such as input containing a very long timezone name. The ecpg library contained these vulnerabilities along with some of its own.

CVE-2014-0064 CVE-2014-2669 Prevent buffer overrun due to integer overflow in size calculations (Noah Misch, Heikki Linnakangas) Several functions, mostly type input functions, calculated an allocation size without checking for overflow. If overflow did occur, a too-small buffer would be allocated and then written past.

CVE-2014-0065 Prevent overruns of fixed-size buffers (Peter Eisentraut, Jozef Mlich) Use strlcpy() and related functions to provide a clear guarantee that fixed-size buffers are not overrun. Unlike the preceding items, it is unclear whether these cases really represent live issues, since in most cases there appear to be previous constraints on the size of the input string. Nonetheless it ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'postgresql-9.1' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg6", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq5", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1.12-0wheezy1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
