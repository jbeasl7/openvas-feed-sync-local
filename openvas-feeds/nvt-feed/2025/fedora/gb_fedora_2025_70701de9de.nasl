# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.707011001019100101");
  script_cve_id("CVE-2025-49113");
  script_tag(name:"creation_date", value:"2025-06-11 04:10:42 +0000 (Wed, 11 Jun 2025)");
  script_version("2025-06-11T05:40:41+0000");
  script_tag(name:"last_modification", value:"2025-06-11 05:40:41 +0000 (Wed, 11 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-70701de9de)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-70701de9de");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-70701de9de");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369709");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the FEDORA-2025-70701de9de advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a **security update** to the stable version 1.6 of Roundcube Webmail.
It provides fixes to recently reported security vulnerabilities:

* Fix Post-Auth RCE via PHP Object Deserialization reported by firs0v.

This version is considered stable and we recommend to update all productive installations of Roundcube 1.6.x with it. Please do backup your data before updating!

CHANGELOG

* Managesieve: Fix match-type selector (remove unsupported options) in delete header action (#9610)
* Improve installer to fix confusion about disabling SMTP authentication (#9801)
* Fix PHP warning in index.php (#9813)
* OAuth: Fix/improve token refresh
* Fix dark mode bug where wrong colors were used for blockquotes in HTML mail preview (#9820)
* Fix HTML message preview if it contains floating tables (#9804)
* Fix removing/expiring redis/memcache records when using a key prefix
* Fix bug where a wrong SPECIAL-USE folder could have been detected, if there were more than one per-type (#9781)
* Fix a default value and documentation of password_ldap_encodage option (#9658)
* Remove mobile/floating Create button from the list in Settings > Folders (#9661)
* Fix Delete and Empty buttons state while creating a folder (#9047)
* Fix connecting to LDAP using ldapi:// URI (#8990)
* Fix cursor position on 'below the quote' reply in HTML mode (#8700)
* Fix bug where attachments with content type of application/vnd.ms-tnef were not parsed (#7119)");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Fedora 42.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.11~1.fc42", rls:"FC42"))) {
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
