# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

eol_cpes = make_array();

# nb:
# - General info about the EOL date for all Adobe products:
#   https://helpx.adobe.com/support/programs/eol-matrix.html
# - Description about the meaning of "Extended support" is available at:
#   https://helpx.adobe.com/x-productkb/policy-pricing/policy_enterprise_lifecycle.html
# - For ColdFusion and Connect the "End of extended support" date has been taken to avoid possible
#   false positives.
# - Older releases (e.g. for Connect) can be extracted from links like e.g.:
#   - https://web.archive.org/web/20200503161900/https://helpx.adobe.com/support/programs/eol-matrix.html
#   - https://web.archive.org/web/20180901000000*/https://helpx.adobe.com/support/programs/eol-matrix.html

eol_cpes[ "cpe:/a:adobe:acrobat_reader" ] = make_array(
  "versions",      "11:2017-10-15;10:2015-11-18;9:2013-06-26;8:2011-11-03;7:2009-12-28",
  "version_regex", "^([0-9]+)"
);

eol_cpes[ "cpe:/a:adobe:coldfusion" ] = make_array(
  "versions",      "2023:2029-05-16;2021:2026-11-10;2018:2024-07-13;2016:2022-02-17;11:2021-04-30;10:2019-05-16;9:2016-12-31;8:2014-07-31;7:unknown;6:unknown;5:unknown;4:unknown;3:unknown;2:unknown;1:unknown",
  "version_regex", "^([0-9]+)"
);

# nb: e.g. 9.1 or 9.2 are not listed on the page but haven been seen "live". For these versions the
# EOL for version 9 on 8/31/2019 have been taken
eol_cpes[ "cpe:/a:adobe:connect" ] = make_array(
  "versions",      "12.1:2027-10-19;12.0:2027-09-15;11.4:2026-12-07;11.3:2026-09-26;11.2:2026-03-10;11.0:2025-09-17;10.8:2025-06-08;10.6:2024-11-17;10.5:2024-07-28;10.0:2023-10-14;9.8:2023-05-14;9.7:2022-11-17;9.6:2022-05-10;9.5:2020-10-31;9.4:2019-08-31;9.3:2019-08-31;9.2:2019-08-31;9.1:2019-08-31;9.0:2019-08-31;8.0:2017-11-30",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# Product phased out by vendor. No EOL statement. Product replaced.
# https://www.advantech.com/products/550836fd-a062-4780-8416-3b742bc7fb16/wise-paas-rmm/mod_8a1ba47e-d09f-4847-b478-42372eea29d1
eol_cpes[ "cpe:/a:advantech:wise-paas%2frmm" ] = make_array(
  "versions",      "3.3.29:2019-07-01",
  "version_regex", "^([0-9]+\.[0-9]+\.[0-9]+)"
);

# https://attic.apache.org/projects/archiva.html
eol_cpes[ "cpe:/a:apache:archiva" ] = make_array(
  "versions", "all:2024-02-01"
);

# https://attic.apache.org/projects/cocoon.html
eol_cpes[ "cpe:/a:apache:cocoon" ] = make_array(
  "versions", "all:2025-01-01"
);

# https://en.wikipedia.org/wiki/Apache_HTTP_Server#Development
eol_cpes[ "cpe:/a:apache:http_server" ] = make_array(
  "versions",      "2.2:2017-12-31;2.0:2013-07-10;1.3:2010-02-03",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# nb: No official EOL notice available / found. Last release of the 2.x branch was in 2015 so all
# versions < 3.x are assumed to be EOL.
eol_cpes[ "cpe:/a:apache:james" ] = make_array(
  "versions",      "2:unknown;1:unknown",
  "version_regex", "^([0-9]+)"
);

# https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces
eol_cpes[ "cpe:/a:apache:log4j" ] = make_array(
  "versions",      "1.2:2015-08-05;1.1:2015-08-05;1.0:2015-08-05",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://struts.apache.org/struts1eol-announcement.html
# https://struts.apache.org/struts1eol-press.html
eol_cpes[ "cpe:/a:apache:struts" ] = make_array(
  "versions",      "1:2013-04-05",
  "version_regex", "^([0-9]+)"
);

# https://tomcat.apache.org/whichversion.html
eol_cpes[ "cpe:/a:apache:tomcat" ] = make_array(
  "versions",      "10.0:2022-10-31;8.5:2024-03-31;8.0:2018-06-30;7.0:2021-03-31;6.0:2016-12-31;5.5:2012-09-30;5.0:2004-08-30;4.1:2009-06-25;4.0:2009-06-25;3.3:2004-03-09;3.2:2004-03-09;3.1:2004-03-09;3.0:2004-03-09",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://apereo.github.io/cas/developer/Maintenance-Policy.html
# nb: We're taking the "Full EOL" date as the security-patch mode (SPM) will still receive security patches...
eol_cpes[ "cpe:/a:apereo:central_authentication_service" ] = make_array(
  "versions",      "6.6:2023-09-02;6.5:2023-02-14;6.4:2022-08-31;6.3:2022-03-31;6.2:2021-06-30;6.1:2020-12-31;6.0:2020-05-01;5.3:2020-10-29;5.2:2019-11-27;5.1:2019-05-30;5.0:unknown;4.2:unknown;4.1:unknown;4.0:unknown;3.6:unknown;3.5:unknown;3.4:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# Those are listed here as being "unsupported":
# https://www.bitvise.com/ssh-server-version-history-7
# https://www.bitvise.com/ssh-server-version-history-6
# https://www.bitvise.com/ssh-server-version-history-5
eol_cpes[ "cpe:/a:bitvise:winsshd" ] = make_array(
  "versions",      "7:unknown;6:unknown;5:unknown",
  "version_regex", "^([0-9]+)"
);

# https://dotcms.com/docs/latest/release-lifecycle
eol_cpes[ "cpe:/a:dotcms:dotcms" ] = make_array(
  "versions",      "4:2019-09-31;3:2018-03-31;2:2015-12-31;1:2013-07-31",
  "version_regex", "^([0-9]+)"
);

# https://checkmk.de/cms_cmk_versionen.html#lifecycle
eol_cpes[ "cpe:/a:checkmk:checkmk" ] = make_array(
  "versions",      "1.6.0:2022-09-08;1.5.0:2021-08-01;1.4.0:2020-05-31;1.2.8:2019-05-04;1.2.6:unknown",
  "version_regex", "^([0-9]+\.[0-9]+\.[0-9]+)"
);

# https://ckeditor.com/docs/ckeditor4/latest/guide/dev_upgrade_ckeditor_3.html
# nb: CKEditor 3 was the first version of that product which replaced FCKeditor 2 and below.
eol_cpes[ "cpe:/a:ckeditor:ckeditor" ] = make_array(
  "versions",      "3:unknown",
  "version_regex", "^([0-9]+)"
);

# https://www.crushftp.com/download.html currently only lists:
# > CrushFTP v9 support ended in October 2022.
# > CrushFTP v10 support will end in March 2027.
# > We only support v10 and v11 now.
#
# For both 9 and 10 versions the last day of the month have been taken.
#
eol_cpes[ "cpe:/a:crushftp:crushftp" ] = make_array(
  "versions",      "10:2027-03-31;9:2022-10-31;8:unknown;7:unknown;6:unknown;5:unknown;4:unknown;3:unknown;2:unknown;1:unknown",
  "version_regex", "^([0-9]+)"
);

# https://www.cisco.com/c/en/us/products/collateral/unified-communications/telepresence-video-communication-server-vcs/eos-eol-notice-c51-743969.html
eol_cpes[ "cpe:/a:cisco:telepresence_video_communication_server_software" ] = make_array(
  "versions", "all:2023-12-31"
);

# https://support.sophos.com/support/s/article/KB-000041566
# nb: The date of the last model reached the EOL has been taken here...
eol_cpes[ "cpe:/a:cyberoam:cyberoam_central_console" ] = make_array(
  "versions", "all:2021-03-31"
);

eol_cpes[ "cpe:/o:cyberoam:cyberoam_os" ] = make_array(
  "versions", "all:2021-03-31"
);

eol_cpes[ "cpe:/a:cyberoam:cyberoam_ssl_vpn" ] = make_array(
  "versions", "all:2014-05-31"
);

# https://www.drupal.org/psa-2023-11-01 # nb: Drupal 9 EOL notice
# https://www.drupal.org/psa-2023-06-07 # nb: Drupal 7 final EOL extension to 05th Jan 2025
# https://www.drupal.org/psa-2022-02-23 # nb: Drupal 7 second EOL extension to Nov 2023
# https://www.drupal.org/psa-2021-11-30 # nb: Drupal 8 EOL notice
# https://www.drupal.org/psa-2020-06-24 # nb: Drupal 7 first EOL extension to Nov 2022
# https://www.drupal.org/psa-2019-02-25 # nb: Initial Drupal 7 EOL notice for Nov 2021
# https://www.drupal.org/forum/general/news-and-announcements/2015-11-09/drupal-6-end-of-life-announcement
# https://www.drupal.org/docs/understanding-drupal/understanding-drupal-version-numbers/legacy-drupal-release-history
eol_cpes[ "cpe:/a:drupal:drupal" ] = make_array(
  "versions",      "9:2023-11-01;8:2021-11-17;7:2025-01-05;6:2016-02-24;5:2007-01-15;4:unknown;3:unknown;2:unknown;1:unknown",
  "version_regex", "^([0-9]+)"
);

# https://jetty.org/download.html#version-history
# nb:
# - Older version branches (e.g. the existence of 7.1 for 7.x) was taken from:
#   https://github.com/jetty/jetty.project/blob/jetty-10.0.x/VERSION.txt
# - 31.12. was taken as the EOL date for the "end year" in the "Years" column of:
#   https://jetty.org/download.html#version-history
# - Only add versions from the page above if the "Status" column contains e.g. "Deprecated" or
#   similar. "EOL / Security Only" versions seems to still receive security updates and shouldn't be
#   marked as EOL
eol_cpes[ "cpe:/a:eclipse:jetty" ] = make_array(
  "versions",      "9.3:2020-12-31;9.2:2018-12-31;9.1:2014-12-31;9.0:2013-12-31;8.1:2014-12-31;8.0:2014-12-31;7.6:2014-12-31;7.5:2014-12-31;7.4:2014-12-31;7.3:2014-12-31;7.2:2014-12-31;7.1:2014-12-31;7.0:2014-12-31;6.1:2010-12-31;6.0:2010-12-31;5.1:2009-12-31;5.0:2009-12-31;4.2:2006-12-31;4.1:2006-12-31;4.0:2006-12-31;3.1:2002-12-31;3.0:2002-12-31;2.4:2000-12-31;2.3:2000-12-31;2.2:2000-12-31;2.1:2000-12-31;2.0:2000-12-31;1.3:1998-12-31;1.2:1998-12-31;1.1:1998-12-31;1.0:1998-12-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.efrontlearning.com/migration
eol_cpes[ "cpe:/a:efrontlearning:efront" ] = make_array(
  "versions",      "3.6:2017-09-15;3.5:unknown;2.5:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.elastic.co/support/eol
eol_cpes[ "cpe:/a:elastic:elasticsearch" ] = make_array(
  "versions",      "7.5:2021-06-02;7.4:2021-04-01;7.3:2021-01-31;7.2:2020-12-25;7.1:2020-11-20;7.0:2020-10-10;6.8:2020-11-20;6.7:2020-09-26;6.6:2020-07-29;6.5:2020-05-14;6.4:2020-02-23;6.3:2019-12-13;6.2:2019-08-06;6.1:2019-06-13;6.0:2019-05-14;5.6:2019-03-11;5.5:2019-01-06;5.4:2018-11-04;5.3:2018-09-28;5.2:2018-07-31;5.1:2018-06-08;5.0:2018-04-26;2.4:2018-02-28;2.3:2017-09-30;2.2:2017-08-02;2.1:2017-05-24;2.0:2017-04-28;1.7:2017-01-16;1.6:2016-12-09;1.5:2016-09-23;1.4:2016-05-05;1.3:2016-01-23;1.2:2015-11-22;1.1:2015-09-25;1.0:2015-08-12",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.elastic.co/support/eol
eol_cpes[ "cpe:/a:elastic:kibana" ] = make_array(
  "versions",      "7.5:2021-06-02;7.4:2021-04-01;7.3:2021-01-31;7.2:2020-12-25;7.1:2020-11-20;7.0:2020-10-10;6.8:2020-11-20;6.7:2020-09-26;6.6:2020-07-29;6.5:2020-05-14;6.4:2020-02-23;6.3:2019-12-13;6.2:2019-08-06;6.1:2019-06-13;6.0:2019-05-14;5.6:2019-03-11;5.5:2019-01-06;5.4:2018-11-04;5.3:2018-09-28;5.2:2018-07-31;5.1:2018-06-08;5.0:2018-04-26;4.6:2018-02-28;4.5:2017-09-30;4.4:2017-08-02;4.3:2017-05-24;4.2:2017-04-28;4.1:2016-11-10;4.0:2016-07-19;3.1:2015-11-15;3.0:2015-09-18",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.elastic.co/support/eol
eol_cpes[ "cpe:/a:elastic:logstash" ] = make_array(
  "versions",      "7.5:2021-06-02;7.4:2021-04-01;7.3:2021-01-31;7.2:2020-12-25;7.1:2020-11-20;7.0:2020-10-10;6.8:2020-11-20;6.7:2020-09-26;6.6:2020-07-29;6.5:2020-05-14;6.4:2020-02-23;6.3:2019-12-13;6.2:2019-08-06;6.1:2019-06-13;6.0:2019-05-14;5.6:2019-03-11;5.5:2019-01-06;5.4:2018-11-04;5.3:2018-09-28;5.2:2018-07-31;5.1:2018-06-08;5.0:2018-04-26;2.4:2018-02-28;2.3:2017-09-30;2.2:2017-08-02;2.1:2017-05-24;2.0:2017-04-28;1.5:2016-11-14;1.4:2015-09-20;1.3:2015-06-11",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://my.f5.com/manage/s/article/K5903
# nb:
# - End of Software Development (EoSD) = No security fixes
# - Only versions down to 10.x has been added for now
# - Some versions of older branches had a different EOL date (e.g. 11.5.0 = 2017, 11.5.1 = 2019,
#   11.5.2+ = 2020) but as all versions are already EOL the newest one has been taken here
eol_cpes[ "cpe:/h:f5:big-ip" ] = make_array(
  "versions",      "17.1:2027-03-31;17.0:2023-07-31;16.1:2025-07-31;16.0:2021-10-07;15.1:2024-12-31;15.0:2020-08-23;14.1:2023-12-31;14.0:2019-11-09;13.1:2023-12-31;13.0:2019-05-22;12.1:2022-05-18;12.0:2017-12-02;11.6:2022-05-10;11.5:2020-04-08;11.4:2017-09-17;11.3:2015-12-17;11.2:2018-12-31;11.1:2014-11-28;11.0:2014-08-24;10.2:2016-12-31;10.1:2016-03-01;10.0:2013-08-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://my.f5.com/manage/s/article/K15073
# nb: End of Software Development (EoSD) = No security fixes
eol_cpes[ "cpe:/a:f5:big-iq_centralized_management" ] = make_array(
  "versions",      "8.3.0:2025-04-13;8.2.0:2024-04-26;8.1.0:2023-06-30;8.0.0:2023-02-24;7.1.0:2022-04-22;7.0.0:2021-08-09;6.1.0:2020-12-07;6.0.1:2020-08-09;6.0.0:2020-05-31;5.4.0:2019-12-27;5.3.0:2019-07-13;5.2.0:2019-04-26;5.1.0:2018-09-21;5.0.0:2018-06-13;4.6.0:2017-11-23;4.5.0:2017-01-27;4.4.0:2016-09-10;4.3.0:2016-02-26;4.2.0:2015-12-20;4.1.0:2015-08-15;4.0.0:2015-04-29",
  "version_regex", "^([0-9]+\.[0-9]+\.[0-9]+)"
);

# https://my.f5.com/manage/s/article/K15280
# https://my.f5.com/manage/s/article/K26270159
# nb: All versions are EOL since 2018 so we're not maintaining a list of EOL dates here and just use
# the latest one for the "all" string
eol_cpes[ "cpe:/a:f5:linerate" ] = make_array(
  "versions", "all:2018-06-30"
);

eol_cpes[ "cpe:/a:ftpdmin:ftpdmin" ] = make_array(
  "versions",      "0.96:2004-06-07",
  "version_regex", "^([0-9]\.[0-9]+)"
);

# https://docs.github.com/en/enterprise-server@latest/admin/all-releases
# nb:
# - Aged 11.10 hasn't been added here to not interfere with possible "new" 11.x releases in the future
# - Older release documentation used "Deprecated date" in the date column while newer using
#   "Closing down date". Those are both the dates which are used below as the EOL one
# - At least for versions 3.12 through 3.9 the vendor moved the date a little (e.g. 3.12 had
#   initially a date of 2025-03-05) so this needs to be checked from time to time
eol_cpes[ "cpe:/a:github:github_enterprise" ] = make_array(
  "versions",      "3.16:2026-03-11;3.15:2025-12-19;3.14:2025-08-27;3.13:2025-06-04;3.12:2025-04-03;3.11:2024-12-19;3.10:2024-09-25;3.9:2024-07-26;3.8:2024-03-26;3.7:2024-01-04;3.6:2023-09-25;3.5:2023-06-29;3.4:2023-03-23;3.3:2023-01-18;3.2:2022-10-12;3.1:2022-06-30;3.0:2022-02-16;2.22:2021-09-23;2.21:2021-06-09;2.20:2021-03-02;2.19:2020-11-12;2.18:2020-08-20;2.17:2020-05-23;2.16:2020-01-22;2.15:2019-10-16;2.14:2019-07-12;2.13:2019-03-27;2.12:2018-12-12;2.11:2018-09-13;2.10:2018-06-05;2.9:2018-03-01;2.8:2017-11-09;2.7:2017-08-03;2.6:2017-04-26;2.5:2017-03-14;2.4:2017-02-09;2.3:2016-11-01;2.2:2016-08-03;2.1:2016-04-26;2.0:2016-02-09;",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# Mapping between the older GVM and GOS releases and also includes a few EOL dates:
# https://greenbone.github.io/docs/latest/faq.html#which-release-contains-which-component
#
# https://forum.greenbone.net/t/greenbone-community-edition-21-04-end-of-life/13837
# https://forum.greenbone.net/t/gvm-21-04-end-of-life-initial-release-2021-04-16/8942
# https://forum.greenbone.net/t/gvm-20-08-end-of-life-initial-release-2020-08-12/6312
# https://forum.greenbone.net/t/gvm-11-end-of-life-initial-release-2019-10-14/3674
# https://forum.greenbone.net/t/gvm-10-end-of-life-initial-release-2019-04-05/208
# https://forum.greenbone.net/t/gvm-9-end-of-life-initial-release-2017-03-07/211
# http://lists.wald.intevation.org/pipermail/openvas-announce/2018-March/000216.html
# http://lists.wald.intevation.org/pipermail/openvas-announce/2016-May/000194.html
# http://lists.wald.intevation.org/pipermail/openvas-announce/2015-April/000181.html
# http://lists.wald.intevation.org/pipermail/openvas-announce/2014-August/000166.html
# http://lists.wald.intevation.org/pipermail/openvas-announce/2013-August/000155.html
# http://lists.wald.intevation.org/pipermail/openvas-announce/2012-September/000143.html
# http://lists.wald.intevation.org/pipermail/openvas-announce/2011-June/000127.html
# http://lists.wald.intevation.org/pipermail/openvas-announce/2009-December/000084.html
#
# nb:
# - For GSA we don't need separate EOL dates (GVM vs. GOS) because on GOS the GSA version is not exposed.
# - For newer GSA versions the version is also not exposed via HTTP anymore, we still keeping this info
#   here as we might have a local detection in the future
# - As it wasn't clear when the switch from 20.08 to 21.4/22.4 (dropped "0") happened (e.g. some early 21.4
#   versions might have used 21.04.1) we're keeping both variants for 21.4+ here and in the manager CPE below.
eol_cpes[ "cpe:/a:greenbone:greenbone_security_assistant" ] = make_array(
  "versions",      "21.4:2023-01-17;21.04:2023-01-17;20.08:2021-12-02;9.0:2020-12-31;8.0:2020-12-31;7.0:2019-10-14;6.0:2018-08-27;5.0:2016-05-10;4.0:2015-04-27;3.0:2014-08-28;2.0:2013-08-07;1.0:2012-09-05",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# nb:
# - 6.0.x is basically EOL since 2018-08-27 (see link above) but GOS 3.1 (using that version) was supported until 2019-07-31.
# - 7.0.x is basically EOL since 2019-10-14 (see GVM-9 link above) but GOS 4.x up to 4.3 (using that version) was supported until 2021-02-22.
# - 8.0.x is basically EOL since 2020-12-31 (see GVM-10 link above) but GOS 5.x (using that version) was supported until 2021-02-22.
# - 9.0.x is basically EOL since 2020-12-31 (see GVM-11 link above) but GOS 6.x (using that version) was supported until 2021-02-22.
# - 20.08.x from GVM and GOS 20.08.x (using that version) was supported until 2021-12-02.
#
# Unfortunately we are not able to differ between both installations on slaves if they are only reachable via OMP/GMP and would report
# a false positive in this case if the earlier date is used.
eol_cpes[ "cpe:/a:openvas:openvas_manager" ] = make_array(
  "versions",      "7.0:2021-02-22;6.0:2019-07-31;5.0:2016-05-10;4.0:2015-04-27;3.0:2014-08-28;2.0:2013-08-07;1.0:2012-09-05",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# nb:
# - Starting from version 8.0 a new product name and CPE is used.
# - We also use e.g. the EOL date of GOS 6 for gvmd 9.0 instead of the EOL date of GVM-11 to avoid false positives for the reasons explained above.
# - See the note on 21.04 vs. 21.4 above
eol_cpes[ "cpe:/a:greenbone:greenbone_vulnerability_manager" ] = make_array(
  "versions",      "21.4:2023-01-17;21.04:2023-01-17;20.08:2021-12-02;9.0:2021-02-22;8.0:2021-02-22",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www-01.ibm.com/software/support/lifecycleapp/PLCSearch.wss?q=lotus+domino&ibm-search=Search
eol_cpes[ "cpe:/a:ibm:lotus_domino" ] = make_array(
  "versions",      "8.5:2018-09-30;8.0:2015-04-30;7.0:2011-04-30;6.5:2010-04-30;6.0:2007-04-30;5.0:2005-09-30",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.ilias.de/docu/goto.php?target=wiki_1357&client_id=docu#ilPageTocA115
# https://www.ilias.de/docu/ilias.php?ref_id=1719&obj_id=6543&cmd=layout&cmdClass=illmpresentationgui&cmdNode=wc&baseClass=ilLMPresentationGUI
# nb: The EOL dates for the older releases where no such date is available the date of the last release of the branch was taken from the second link
# nb: Starting with version 6 ILIAS changed versioning scheme to 6.x instead of previous 5.x.y.
#     Thus, from 6.x onwards the branches reaching EOL will be 6, 7 etc. and will be handled in the VT itself, as they do not match the version_regex anymore.
eol_cpes[ "cpe:/a:ilias:ilias" ] = make_array(
  "versions",      "5.4:2021-12-31;5.3:2020-08-21;5.2:2019-06-06;5.1:2018-08-01;5.0:2017-07-31;4.4:2016-07-31;4.3:2015-07-28;4.2:2014-07-31;4.1:2013-02-03;4.0:2012-02-03;3.10:2010-10-06;3.9:2010-02-01;3.8:2008-02-04;3.7:2007-07-26;3.6:2007-07-26;3.5:2006-10-23;3.4:2006-09-05;3.3:2005-03-09;3.2:2005-02-04;3.1:2004-07-11;3.0:2004-06-21;2.4:2004-06-21",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.isc.org/downloads/
#
# nb: This seems to be currently not maintained/up2date:
# https://kb.isc.org/docs/bind-9-end-of-life-dates
eol_cpes[ "cpe:/a:isc:bind" ] = make_array(
  "versions",      "9.15:2020-01-31;9.14:2020-04-30;9.13:unknown;9.12:2019-05-31;9.11:2021-12-31;9.10:2018-07-31;9.9:2018-07-31;9.8:2014-09-30;9.7:2012-11-30;9.6:2014-02-28;9.5:2010-07-30;9.4:2009-12-31;9.3:2008-12-31;9.2:2007-09-30;9.1:2001-07-31;8.99:2007-08-31;4.99:2001-12-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

eol_cpes[ "cpe:/a:ispyconnect:ispy" ] = make_array(
  "versions", "all:unknown"
);

eol_cpes[ "cpe:/a:jetbrains:upsource" ] = make_array(
  "versions", "all:2023-01-31"
);

# https://docs.joomla.org/What_version_of_Joomla!_should_you_use%3F
# nb: The EOL date is always the release date of the next major release, e.g.
# 3.8.0 released 2017-09-19 -> EOL of 3.7
eol_cpes[ "cpe:/a:joomla:joomla" ] = make_array(
  "versions",      "3.8:2018-10-30;3.7:2017-09-19;3.6:2017-04-25;3.5:2016-07-12;3.4:2016-03-21;3.3:2015-02-24;3.2:2014-10-01;3.1:2013-12-01;3.0:2013-05-01;2.5:2014-12-31;1.7:2012-02-01;1.6:2011-08-01;1.5:2012-09-01;1.0:2009-07-22",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://github.com/jquery/jquery.com/pull/163
eol_cpes[ "cpe:/a:jquery:jquery" ] = make_array(
  "versions",      "2:unknown;1:unknown",
  "version_regex", "^([0-9]+)"
);

# https://support.juniper.net/support/eol/software/junos/
eol_cpes[ "cpe:/o:juniper:junos" ] = make_array(
  "versions",      "22.4:2026-06-22;22.3:2025-03-28;22.2:2025-12-23;22.1:2024-09-24;21.4:2025-06-20;21.3:2024-03-23;21.2:2024-12-29;21.1:2023-09-25;20.4:2024-06-25;20.3:2023-03-29;20.2:2023-12-30;20.1:2022-09-27;19.4:2023-06-26;19.3:2023-03-26;19.2:2022-12-26;19.1:2022-09-27;18.4:2022-06-22;18.3:2022-03-26;18.2:2021-12-29;18.1:2021-09-28;17.4:2021-06-21;17.3:2021-02-25;17.2:2020-12-06;17.1:2020-09-03;16.2:2020-05-29;16.1:2020-01-25;15.1X53:2018-12-05;15.1X49:2021-06-30;15.1:2018-12-05;14.2:2018-05-05;14.1X53:2019-06-30;14.1:2018-06-13;13.3:2017-07-22;13.2X52:2017-06-30;13.2X51:2016-06-30;13.2X50:2014-12-28;13.2:2016-02-29;13.1X50:2015-12-30;13.1:2015-09-15;12.3X54:2018-07-18;12.3X52:2016-02-23;12.3X51:2015:09-15;12.3X50:2016-07-31;12.3X48:2022-06-30;12.3:2016-07-31;12.2X50:2015-07-31;12.2:2015-03-05;12.1X49:2014-10-19;12.1X48:2015-06-30;12.1X47:2017-02-18;12.1X46:2017-06-30;12.1X45:2015-01-17;12.1X44:2016-07-18;12.1:2014-09-28;11.4:2015-06-21;11.3:2013-03-15;11.2:2013-02-15;11.1:2012-05-15;10.4:2014-06-08;10.3:2011-12-21;10.2:2011-11-15;10.1:2011-05-15;10.0:2013-05-15;9.6:2010-11-06;9.5:2010-08-15;9.4:2010-05-11;9.3:2012-05-15;9.2:2009-11-12;9.1:2009-07-28;9.0:2009-05-15;8.5:2011-05-16;8.4:2008-11-09;8.3:2008-07-18;8.2:2008-05-15;8.1:2010-05-06;8.0:2007-11-15;7.6:2007-08-15;7.5:2007-05-08;7.4:2007-02-15;7.3:2006-11-16;7.2:2006-08-14;7.1:2006-05-14;7.0:2006-02-15;6.4:2005-11-12;6.3:2005-08-15;6.2:2005-05-15;6.1:2005-02-15;6.0:2004-11-15;5.7:2004-08-15;5.6:2004-05-15;5.5:2004-02-15;5.4:2003-11-15;5.3:2003-08-15;5.2:2003-05-15;5.2:2003-05-15;5.1:2003-02-15;5.0:2002-11-15;4.4:unknown",
  "version_regex", "^([0-9.]+)(X[0-9]+)?"
);

# https://dev.lucee.org/t/lucee-roadmap-update/12746 says:
# > Lucee 5.3 is EOL, no more releases (aside from security fixes)
# Older versions have been taken from:
# - https://dev.lucee.org/c/news/release/8
# - https://download.lucee.org/
# - https://dev.lucee.org/t/end-of-life-for-lucee-4-5/4093
eol_cpes[ "cpe:/a:lucee:lucee_server" ] = make_array(
  "versions",      "5.2:unknown;5.1:unknown;5.0:unknown;4.5:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://magento.com/blog/magento-news/supporting-magento-1-through-june-2020
eol_cpes[ "cpe:/a:magentocommerce:magento" ] = make_array(
  "versions",      "1:2020-07-01",
  "version_regex", "^([0-9])"
);

# https://mariadb.org/about/maintenance-policy/
eol_cpes[ "cpe:/a:mariadb:mariadb" ] = make_array(
  "versions",      "10.4:2024-06-18;10.3:2023-05-25;10.2:2022-05-23;10.1:2020-10-17;10.0:2019-03-31;5.5:2020-04-11;5.3:2017-03-01;5.2:2015-11-10;5.1:2015-02-01",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://docs.mattermost.com/administration/extended-support-release.html
# https://docs.mattermost.com/administration/release-lifecycle.html
eol_cpes[ "cpe:/a:mattermost:mattermost_server" ] = make_array(
  "versions",      "5.31:2021-10-15;5.30:2021-03-15;5.29:2021-02-15;5.28:2021-01-15;5.27:2020-12-15;5.26:2020-11-15;5.25:2021-04-15;5.24:2020-09-15;5.23:2020-08-15;5.22:2020-07-15;5.21:2020-06-15;5.20:2020-05-15;5.19:2020-10-15;5.18:2020-03-15;5.17:2020-02-15;5.16:2020-01-15;5.15:2019-12-15;5.14:2019-11-15;5.13:2019-09-15;5.12:2019-08-15;5.11:2019-07-15;5.10:2019-06-15;5.9:2020-04-15;5.8:2019-04-15;5.7:2019-03-15;5.6:2019-02-15;5.5:2019-01-15;5.4:2018-12-15;5.3:2018-11-15;5.2:2018-10-15;5.1:2018-09-15;5.0:2018-08-15;4.10:2019-07-15;4.9:2018-06-15;4.8:2018-05-15;4.7:2018-04-15;4.6:2018-03-15;4.5:2018-02-15;4.4:2018-01-15;4.3:2017-12-15;4.2:2017-11-15;4.1:2017-10-15;4.0:2017-09-15",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# General:
# https://www.mcafee.com/enterprise/en-au/support/product-eol.html
#
# https://kc.mcafee.com/corporate/index?page=content&id=KB85857
eol_cpes[ "cpe:/a:mcafee:email_gateway" ] = make_array(
  "versions",      "7.6:2016-10-12",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://kc.mcafee.com/corporate/index?page=content&id=KB88252
eol_cpes[ "cpe:/a:mcafee:epolicy_orchestrator" ] = make_array(
  "versions",      "5.3:2019-03-31;5.1:2017-12-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://kc.mcafee.com/corporate/index?page=content&id=KB86212
eol_cpes[ "cpe:/a:mcafee:virusscan_enterprise_for_linux" ] = make_array(
  "versions",      "2.0.2:2017-12-31;2.0.1:2016-12-31;2.0.0:2016-12-31;1.9.1:2017-12-31;1.9.0:2016-12-31",
  "version_regex", "^([0-9]+\.[0-9]+\.[0-9]+)"
);

# https://kc.mcafee.com/corporate/index?page=content&id=KB88950
eol_cpes[ "cpe:/a:mcafee:web_gateway" ] = make_array(
  "versions",      "7.7:2019-12-31;7.6:2018-12-31;7.5:2017-12-31;7.4:2016-12-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.mediawiki.org/wiki/Version_lifecycle
eol_cpes[ "cpe:/a:mediawiki:mediawiki" ] = make_array(
  "versions",      "1.37:2022-11-31;1.36:2022-05-31;1.35:2023-09-30;1.34:2020-11-30;1.33:2020-06-30;1.32:2020-01-31;1.31:2021-09-30;1.30:2019-06-06;1.29:2018-07-31;1.28:2017-11-30;1.27:2019-06-30;1.26:2016-11-30;1.25:2016-06-01;1.24:2015-10-01;1.23:2017-04-01;1.22:2014-11-01;1.21:2014-05-01;1.20:2013-10-01;1.19:2015-03-01;1.18:2012-11-01;1.17:2012-03-01;1.16:2011-03-01;1.15:2010-06-01;1.14:2009-05-01;1.13:2009-02-01;1.12:2009-01-15;1.11:2008-02-01;1.10:2008-02-01;1.9:2008-02-01;1.8:2007-08-01;1.7:2007-02-01;1.6:2009-02-01;1.5:2006-03-01;1.4:2006-03-01;1.3:2005-10-01;1.2:2004-02-01;1.1:2004-01-01",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.meinbergglobal.com/english/news/end-of-life-announcement-for-meinberg-lantime-operating-system-version-6.htm
# Notes:
# - A few models are completely discontinued and these are checked separately in gsf/2023/meinberg/gb_meinberg_lantime_eol.nasl
# - Only V5, V6 and V7 devices/versions are known / have been tested
eol_cpes[ "cpe:/o:meinbergglobal:lantime_firmware" ] = make_array(
  "versions",      "6:2023-01-01;5:unknown;4:unknown;3:unknown;2:unknown;1:unknown",
  "version_regex", "^([0-9]+)"
);

# https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=exchange%20server&Filter=FilterNO
# https://en.wikipedia.org/wiki/History_of_Microsoft_Exchange_Server#Version_history
# https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates
eol_cpes[ "cpe:/a:microsoft:exchange_server" ] = make_array(
  "versions",      "2013sp3:2017-10-01;2013sp2:2017-01-01;2013sp1:2017-01-01;2013:2017-01-01;2007:2017-01-01;5.5:2010-01-01",
  "version_regex", "^([0-9]+)(\.)?(sp[0-9]+)?"
);

# Special handling for Exchange Server detected via OWA because the used versioning scheme
# currently differs. Build version -> Exchange version mapping.
# 14.0 - 14.3 -> Exchange 2010
# 8.0 - 8.3 -> Exchange 2007
# 6.5 -> Exchange 2003
# 6.0 -> Exchange 2000
eol_cpes[ "cpe:/a:microsoft:outlook_web_app" ] = make_array(
  "versions",      "14.3:2020-10-13;14.2:2020-10-13;14.1:2020-10-13;14.0:2020-10-13;8.3:2017-04-11;8.2:2017-04-11;8.1:2017-04-11;8.0:2017-04-11;6.5:2014-04-08;6.0:2010-01-11;5.5:2006-01-10;5.0:2006-01-10;4.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# IIS EOL dates are mostly coupled to the EOL of the OS, see eol_os.inc
eol_cpes[ "cpe:/a:microsoft:internet_information_services" ] = make_array(
  "versions",      "6.0:2015-07-14;5.1:2014-04-08;5.0:2010-07-13;4.0:2002-12-31;3.0:2002-12-31;2.0:2002-12-31;1.0:2000-09-30",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=sharepoint%20foundation&Filter=FilterNO
eol_cpes[ "cpe:/a:microsoft:sharepoint_foundation" ] = make_array(
  "versions",      "2013sp1:2023-04-11;2013:2015-04-14;2010sp2:2020-10-13;2010sp1:2014-10-14;2010:2012-07-10",
  "version_regex", "^([0-9]+)(\.)?(sp[0-9]+)?"
);

# https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=sharepoint%20server&Filter=FilterNO
eol_cpes[ "cpe:/a:microsoft:sharepoint_server" ] = make_array(
  "versions",      "2016:2026-07-14;2013sp1:2023-04-11;2013:2015-04-14;2010sp2:2020-10-13;2010sp1:2014-10-14;2010:2012-07-10;2007sp3:2017-10-10;2007sp2:2013-01-08;2007sp1:2010-07-13;2007:2009-01-13;2003:2014-04-08",
  "version_regex", "^([0-9.+)(\.)?(sp[0-9]+)?"
);

# https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=sql%20server&Filter=FilterNO
# https://en.wikipedia.org/wiki/History_of_Microsoft_SQL_Server#Release_summary
# e.g. https://docs.microsoft.com/en-us/lifecycle/products/sql-server-2016
# https://docs.microsoft.com/en-us/lifecycle/products/microsoft-sql-server-2008
# Note: The version needs to be the same as returned by get_app_version() (e.g. '2014 SP2' will be '2014sp2')
eol_cpes[ "cpe:/a:microsoft:sql_server" ] = make_array(
  "versions",      "1.0:unknown;1.1:unknown;4.2:unknown;6.0:unknown;6.5:unknown;7.0:unknown;2000:unknown;2005:2007-07-10;2005sp1:2008-04-08;2005sp2:2010-01-12;2005sp3:2012-01-10;2005sp4:2016-04-12;2008:2010-04-13;2008sp1:2011-10-11;2008sp2:2012-10-09;2008sp3:2015-10-13;2008sp4:2019-07-09;2008r2:2012-07-10;2008r2sp1:2013-10-08;2008r2sp2:2015-10-13;2008r2sp3:2020-07-14;2012:2014-01-14;2012sp1:2015-07-14;2012sp2:2017-01-10;2012sp3:2018-10-09;2012sp4:2022-07-12;2014:2016-07-12;2014sp1:2017-10-10;2014sp2:2020-01-14;2014sp3:2024-07-09;2016:2018-01-09;2016sp1:2019-07-09;2016sp2:2022-10-11;2016sp3:2026-07-14;",
  "version_regex", "^([0-9a-z]+)"
);

# https://learn.microsoft.com/en-us/lifecycle/products/?terms=skype%20for%20business%20server
# nb:
# - "Extended End Date" has been taken for now
# - Skype for Business Server 2019 and 2015 have both the same EOL date
eol_cpes[ "cpe:/a:microsoft:skype_for_business" ] = make_array(
  "versions", "all:2025-10-14"
);

# From https://support.nagios.com/forum/viewtopic.php?f=16&t=64655:
# > We only support versions of XI that are less than twenty four months from their release date.
#
# The relevant versions can be found here:
# - https://www.nagios.com/changelog/#nagios-xi (only starting from 2011)
# - https://assets.nagios.com/downloads/nagiosxi/versions.php
#
# nb:
# - For the EOL date the release date of the last version of the relevant branch (e.g. 5.2.9 for
#   5.2.x) has been taken and then 2 years have been added
# - Only the ones which have already reached their EOL have been added (e.g. 5.9.3 was released on
#   02/1/23 so it wasn't added here)
# - There was e.g. no 2013 or 2010 version according to the changelog but we still have added it
#   here (with an "unknown" date) just to be sure if these are just not mentioned on the changelogs
eol_cpes[ "cpe:/a:nagios:nagios_xi" ] = make_array(
  "versions",      "5.7:2022-12-08;5.6:2022-04-21;5.5:2021-02-28;5.4:2020-03-13;5.3:2018-12-14;5.2:2018-06-10;2014:2017-04-23;2013:unknown;2012:2016-02-11;2011:2014-08-22;2010:unknown;2009:2013-02-02",
  # nb: Regex is used to either only extract:
  # - 2012 from e.g. 2012r2.9
  # - 5.9 from e.g. 5.9.3
  "version_regex", "^(([0-9]+\.[0-9]+|20[0-9]{2}))"
);

# https://endoflife.date/nginx
eol_cpes[ "cpe:/a:nginx:nginx" ] = make_array(
  "versions",      "1.21:2022-05-24;1.20:2022-05-24;1.18:2021-04-20;1.16:2020-04-20;1.14:2019-04-23;1.12:2018-04-17;1.10:2017-04-12;1.8:2016-04-26;1.6:2015-04-21;1.4:2014-04-24;1.2:2013-04-24;1.0:2012-04-23",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# mysql:mysql is <= 5.5.9, newer versions have oracle:mysql
# https://en.wikipedia.org/wiki/MySQL#Release_history
# https://www.mysql.com/support/eol-notice.html (Sustaining Support means EOL)
# http://www.oracle.com/us/support/library/lifetime-support-technology-069183.pdf
eol_cpes[ "cpe:/a:mysql:mysql" ] = make_array(
  "versions",      "5.1:2013-12-04;5.0:2012-01-09;4.1:2009-12-31;4.0:2008-12-31;3.2:2006-08-01",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# No EOL versions yet
eol_cpes[ "cpe:/a:oracle:mysql" ] = make_array(
  "versions",      "",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.microfocus.com/productlifecycle/
eol_cpes[ "cpe:/a:netiq:access_manager" ] = make_array(
  "versions",      "5.0:2025-04-30;4.5:2023-07-31;4.4:2020-07-31;4.3:2018-09-30;4.2:2017-11-30;4.1:2016-11-30;4.0:2016-05-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.microfocus.com/lifecycle/
eol_cpes[ "cpe:/a:netiq:edirectory" ] = make_array(
  "versions",      "9.1:2020-09-30;9.0:2019-02-01;8.8:2017-10-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.microfocus.com/lifecycle/
eol_cpes[ "cpe:/a:netiq:imanager" ] = make_array(
  "versions",      "3.0:2020-09-30;2.7:2017-10-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);
eol_cpes[ "cpe:/a:novell:imanager" ] = make_array(
  "versions",      "3.0:2020-09-30;2.7:2017-10-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.microfocus.com/lifecycle/
eol_cpes[ "cpe:/a:netiq:sentinel" ] = make_array(
  "versions",      "8.2:2020-07-31;8.1:2019-07-31;8.0:2018-06-30;7.4:2017-11-30;7.3:2016-12-31;7.2:2016-02-29;7.1:2015-07-31;7.0:2014-06-30",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.microfocus.com/lifecycle/
# nb: versions 2014 & 2012 have been reduced to 14 & 12
# TODO: version not yet determined by detection script
eol_cpes[ "cpe:/a:novell:groupwise" ] = make_array(
  "versions",      "18:2020-12-11;14:2018-06-30;12:2015-06-30;8:2014-06-30;7:2010-04-02",
  "version_regex", "^([0-9]+)"
);

# https://www.microfocus.com/lifecycle/
eol_cpes[ "cpe:/a:novell:open_enterprise_server" ] = make_array(
  "versions",      "2018:2022-11-28;2015.sp1:2019-12-31;2015:2017-06-14;11sp3:2017-06-13;11sp2:2017-06-13;11sp1:2015-01-29:11:2013-08-28;2sp3:2012-12-22;2sp2:2009-11-11;2sp1:2008-12-01",
  "version_regex", "^([0-9]+)(\.)?([sp0-9]+)?"
);

# https://www.microfocus.com/lifecycle/
eol_cpes[ "cpe:/a:novell:service_desk" ] = make_array(
  "versions",      "7:2018-04-27",
  "version_regex", "^([0-9]+)"
);

# https://openssl-library.org/policies/releasestrat/index.html
# nb: As of 07/2025 the 3.1 version wasn't included on the page above anymore and the info had been
# extracted from an older version of the page which is also available here:
# https://web.archive.org/web/20240702234418/https://www.openssl.org/policies/releasestrat.html
eol_cpes[ "cpe:/a:openssl:openssl" ] = make_array(
  "versions",      "3.5:2030-04-08;3.4:2026-10-22;3.3:2026-04-09;3.2:2025-11-23;3.1:2025-03-14;3.0:2026-09-07;1.1.1:2023-09-11;1.1.0:2019-09-11;1.0.2:2019-12-31;1.0.1:2016-07-06;1.0.0:2016-07-06;0.9.8:2014-12-23",
  "version_regex", "^([0-9]+\.[0-9]+\.[0-9]+)"
);

# https://openwrt.org/releases/start
eol_cpes[ "cpe:/a:openwrt:openwrt" ] = make_array(
  "versions",      "17.01:unknown;18.06:unknown;19.07:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://en.wikipedia.org/wiki/OTRS
# (EOL is release of next major version or last patch for the current version, whatever comes last)
eol_cpes[ "cpe:/a:otrs:otrs" ] = make_array(
  "versions",      "3.3:2015-09-23;3.2:2015-09-23;3.1:2014-03-27;3.0:2013-07-04;2.4:2012-09-20;2.3:2010-02-06;2.2:2010-02-06;2.1:2010-02-06;2.0:2007-07-19;1.3:2005-11-20;1.2:2004-09-22;1.1:2004-02-10;1.0:2003-04-24",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://github.com/owncloud/core/wiki/Maintenance-and-Release-Schedule
eol_cpes[ "cpe:/a:owncloud:owncloud" ] = make_array(
  "versions",      "9.1:2018-03-31;9.0:2017-12-05;8.2:2017-05-31;8.1:2017-02-28;8.0:2016-10-31;7.0:2016-05-31;6.0:2015-09-01;5.0:2015-03-01;4.5:2013-07-01;4.0:2013-07-01;3.0:2012-04-01;2.0:2012-01-01;1.0:2011-10-01",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://live.paloaltonetworks.com/t5/expedition-articles/important-update-end-of-life-announcement-for-palo-alto-networks/ta-p/589642
eol_cpes[ "cpe:/a:paloaltonetworks:expedition" ] = make_array(
  "versions", "all:2025-01-01"
);

# https://doc.pfsense.org/index.php/Versions_of_pfSense_and_FreeBSD
# https://lists.pfsense.org/pipermail/list/2012-April/002017.html
# EOL date is mainly the release date of the next release
eol_cpes[ "cpe:/a:pfsense:pfsense" ] = make_array(
  "versions",      "2.3:2017-10-12;2.2:2016-04-12;2.1:2015-01-23;2.0:2013-09-15;1.2:2011-09-17;1.1:2008-02-25;1.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://secure.php.net/eol.php and https://secure.php.net/supported-versions.php
eol_cpes[ "cpe:/a:php:php" ] = make_array(
  "versions",      "8.0:2023-11-26;7.4:2022-11-28;7.3:2021-12-06;7.2:2020-11-30;7.1:2019-12-01;7.0:2019-01-10;5.6:2018-12-31;5.5:2016-07-21;5.4:2015-09-03;5.3:2014-08-14;5.2:2011-01-06;5.1:2006-08-24;5.0:2005-09-05;4.4:2008-08-07;4.3:2005-03-31;4.2:2002-09-06;4.1:2002-03-12;4.0:2001-06-23;3.0:2000-10-20",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.phpbb.com/community/viewtopic.php?t=2373956
# https://www.phpbb.com/community/viewtopic.php?f=14&p=14902381#p14902381
# https://www.phpbb.com/community/viewtopic.php?f=14&t=2573411
# https://www.phpbb.com/community/viewtopic.php?f=14&t=1385785
eol_cpes[ "cpe:/a:phpbb:phpbb" ] = make_array(
  "versions",      "3.2:2020-11-07;3.1:2018-07-01;3.0:2017-01-01;2.0:2009-01-01",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://github.com/PHPMailer/PHPMailer#legacy-versions
# Currently everything from https://github.com/PHPMailer/PHPMailer/blob/master/changelog.md < 5.2 is EOL
# nb: Up to 1.73 PHPMailer used no patch level and started to use one with 2.0.0 so the version_regex
# below is just grabbing one digit of the minor version for now.
eol_cpes[ "cpe:/a:phpmailer_project:phpmailer" ] = make_array(
  "versions",      "5.2:2018-12-31;5.1:unknown;5.0:unknown;2.3:unknown;2.2:unknown;2.1:unknown;2.0:unknown;1.7:unknown;1.6:unknown;1.5:unknown;1.4:unknown;1.2:unknown;1.1:unknown;1.0:unknown;0.9:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.phpmyadmin.net/downloads/#support
#
# nb:
# - EOL basically means all branches like 4.2 listed at https://www.phpmyadmin.net/files/
#   but not as "maintained" at https://www.phpmyadmin.net/downloads/
# - While the last version for 4.9 seems to have been released on 2023-02-08 it seems this is a
#   LTS version still supported
eol_cpes[ "cpe:/a:phpmyadmin:phpmyadmin" ] = make_array(
  "versions",      "5.1:2022-05-10;5.0:2021-02-24;4.8:2019-06-04;4.7:2018-04-07;4.6:2017-04-01;4.5:2016-04-01;4.4:2016-10-01;4.3:2015-10-01;4.2:2015-07-01;4.1:2015-01-01;4.0:2017-04-01;3.5:unknown;3.4:unknown;3.3:unknown;3.2:unknown;3.1:unknown;3.0:unknown;2.11:2011-07-12;2.10:unknown;2.9:unknown;2.8:unknown;2.7:unknown;2.6:unknown;2.5:unknown;2.4:unknown;2.3:unknown;2.2:unknown;2.1:unknown;2.0:unknown;1.3:unknown;1.2:unknown;1.1:unknown;0.9:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.plesk.com/lifecycle-policy/
eol_cpes[ "cpe:/a:parallels:parallels_plesk_panel" ] = make_array(
  "versions",      "12:2019-01-01;11:2016-12-13;10:2015-05-03;9:2013-06-09;8:2012-09-01;7:2012-01-01;6:2012-01-01;5:2012-01-01;4:2012-01-01;3:2012-01-01;2:2012-01-01;1:2012-01-01;0:2012-01-01",
  "version_regex", "^([0-9]+)"
);
eol_cpes[ "cpe:/a:plesk:onyx" ] = make_array(
  "versions",      "17:2021-04-20",
  "version_regex", "^([0-9]+)"
);

# https://www.postgresql.org/support/versioning/
# n.b. We are using a list for this EOL CPEs as the version naming changed. The first entry in versions uses the first entry in version_regex later on
eol_cpes[ "cpe:/a:postgresql:postgresql" ] = make_array();
tmp["versions"] = make_list("17:2029-11-08;16:2028-11-09;15:2027-11-11;14:2026-11-12;13:2025-11-13;12:2024-11-14;11:2023-11-09;10:2022-11-10", "9.6:2021-11-11;9.5:2021-02-11;9.4:2020-02-13;9.3:2018-11-08;9.2:2017-11-09;9.1:2016-10-27;9.0:2015-10-08;8.4:2014-07-24;8.3:2013-02-07;8.2:2011-12-05;8.1:2010-11-08;8.0:2010-10-01;7.4:2010-10-01;7.3:2007-11-27;7.2:2007-02-04;7.1:2006-04-13;7.0:2005-05-08;6.5:2004-06-09;6.4:2003-10-30;6.3:2003-03-01");
tmp["version_regex"] = make_list("^([0-9]+)", "^([0-9]+\.[0-9]+)");
eol_cpes[ "cpe:/a:postgresql:postgresql" ] = tmp;

# https://doc.powerdns.com/authoritative/appendices/EOL.html
# https://web.archive.org/web/20201108041150/https://doc.powerdns.com/authoritative/appendices/EOL.html (for some older variants of the docs)
# https://doc.powerdns.com/md/end-of-life/#end-of-life-statements
eol_cpes[ "cpe:/a:powerdns:authoritative_server" ] = make_array(
  "versions",      "4.4:2022-10-20;4.3:2022-01-25;4.2:2021-07-30;4.1:2020-10-31;4.0:unknown;3.4:2017-12-01;3.3:2017-12-01;3.2:2017-12-01;3.1:2017-12-01;3.0:2017-12-01;2.9:2015-05-21",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://doc.powerdns.com/recursor/appendices/EOL.html
eol_cpes[ "cpe:/a:powerdns:recursor" ] = make_array(
  "versions",      "4.5:2022-12-12;4.4:2022-05-30;4.3:2021-12-17;4.2:2021-05-11;4.1:2020-10-19;4.0:unknown;3.7:unknown;3.6:unknown;3.5:unknown;3.3:unknown;3.2:unknown;3.1:unknown;3.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# - Main info: https://community.progress.com/s/products/moveit/product-lifecycle
# - Some of the older versions got taken from advisories listed at
#   https://community.progress.com/s/article/MOVEit-Transfer-Vulnerability-Scanner-Penetration-Testing-and-Hardening-FAQ-s
#   or from older CVEs
# - Retired date and the first day of this month is used
eol_cpes[ "cpe:/a:progress:moveit_transfer" ] = make_array(
  "versions",      "15.0:2025-11-01;14.1:2025-05-01;14.0:2024-10-01;13.1:2024-04-01;13.0:2023-10-01;12.1:unknown;12.0:unknown;11.2:unknown;11.1:unknown;11.0:unknown;10.2:unknown;10.1:unknown;10.0:unknown;9.0:unknown;8.3:unknown;8.2:unknown;8.1:unknown;8.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://pve.proxmox.com/wiki/FAQ
# nb: Usually only the EOL month is given and we're taking the first day of it.
eol_cpes[ "cpe:/a:proxmox:virtual_environment" ] = make_array(
  "versions",      "8:2026-08-01;7:2024-07-01;6:2022-09-01;5:2020-07-01;4:2018-06-01;3:2017-02-01;2:2014-05-01;1:2013-01-01",
  "version_regex", "^([0-9]+)"
);

# nb: There seems to be no "real" EOL date or overview announced / published so the following has been assumed:
# - Publishing date 19.09.2024 of https://www.ivanti.com/blog/cloud-service-appliance-4-6-security-update has been used for the EOL of 4.6
# - 31.12.2021 based on the following mentioned on https://www.ivanti.com/blog/now-available-ivanti-cloud-service-appliance-csa-4-6 for 4.5:
#   > Please note, the current CSA will continue to function after December 31. 2021. However, it will no longer receive patches and updates.
# - For all 4.x versions an "unknown" date has been used
# - all earlier versions are (at least currently) not taken into account
eol_cpes[ "cpe:/a:ivanti:cloud_services_appliance" ] = make_array(
  "versions",      "4.6:2024-09-19;4.5:2021-12-31;4.4:unknown;4.3:unknown;4.2:unknown;4.1:unknown;4.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# - https://forums.ivanti.com/s/article/Pulse-Connect-Secure-Software-Dates-Milestones
# - https://web.archive.org/web/20230201133412/https://support.pulsesecure.net/product-service-policies/eol/software/pulse-connect-secure-software-dates-milestones/ (latest version from Pulse Secure before the docs got moved to ivanti.com)
# - https://forums.ivanti.com/s/article/Granular-Software-Release-EOL-Timelines-and-Support-Matrix
# - https://forums.ivanti.com/s/article/KB43892
#
# nb: A note on the last available security update is available in https://web.archive.org/web/20220529190704/https://support.pulsesecure.net/web/wp-content/uploads/2019/02/PulseSecure_EOL_v2.pdf:
#
# > End of Engineering for Software (EOE) - Critical must-fix security patches are provided, for an approximate period of 12 months, after this date.
#
# Based on this version an EOE date + 12 months is used in the versions part of the array below.
#
eol_cpes[ "cpe:/a:ivanti:connect_secure" ] = make_array(
  "versions",      "9.1:2025-06-30;9.0:2020-10-30;8.3:2019-10-11;8.2:2018-07-11;8.1:2017-12-18;8.0:2016-09-30",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://en.wikipedia.org/wiki/History_of_Python#Table_of_versions
eol_cpes[ "cpe:/a:python:python" ] = make_array(
  "versions",      "3.10:2026-10-31;3.9:2025-10-31;3.8:2024-10-31;3.7:2023-06-30;3.6:2021-12-31;3.5:2020-09-30;3.4:2019-03-18;3.3:2017-09-29;3.2:2016-02-20;3.1:2012-06-30;3.0:2009-06-27;2.7:2020-01-01;2.6:2013-10-29;2.5:2011-05-26;2.4:2008-12-19;2.3:2008-03-11;2.2:2003-05-30;2.1:2002-04-09;2.0:2001-06-22;1.6:2000-09-30;1.5:1999-04-13;1.4:unknown;1.3:unknown;1.2:unknown;1.1:1994-11-10;1.0:1994-02-15;0.9:1993-07-29",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://access.redhat.com/support/policy/updates/jboss_notes/#Life_cycle_dates
# (EOL is the end of ELS-2, as those Life Support date ranges include critical vulnerability fixes which cannot be considered end of life)
eol_cpes[ "cpe:/a:redhat:jboss_enterprise_application_platform" ] = make_array(
  "versions",      "7:2029-05-31;6:2025-06-30;5:2022-11-30;4:2019-11-30",
  "version_regex", "^([0-9]+)"
);

# https://support.ruckuswireless.com/products/50-smartcell-gateway-200-scg200
eol_cpes[ "cpe:/o:ruckuswireless:scg-200_firmware" ] = make_array(
  "versions",      "3:unknown;2:unknown;1:unknown",
  "version_regex", "^([0-9])"
);

# https://access.redhat.com/support/policy/updates/jboss_notes/#Life_cycle_dates
eol_cpes[ "cpe:/a:redhat:jboss_operations_network" ] = make_array(
  "versions",      "3:2019-06-30",
  "version_regex", "^([0-9]+)"
);

# https://wiki.samba.org/index.php/Samba_Release_Planning
eol_cpes[ "cpe:/a:samba:samba" ] = make_array(
  "versions",      "4.8:2019-09-17;4.7:2019-03-19;4.6:2018-09-13;4.5:2018-03-13;4.4:2017-09-21;4.3:2017-03-07;4.2:2016-09-07;4.1:2016-03-22;4.0:2015-09-08;3.6:2015-03-04;3.5:2013-10-11;3.4:2012-12-11;3.3:2011-08-09;3.2:2010-03-01;3.0:2009-08-05",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# http://igss.schneider-electric.com/products/igss/download/licensed-versions.aspx
eol_cpes[ "cpe:/a:schneider-electric:interactive_graphical_scada_system" ] = make_array(
  "versions",      "13.0:unknown;12.0:unknown;11.0:unknown;10.0:unknown;9.0:unknown;8.0:unknown;7.0:unknown;6.0:unknown;5.1:unknown;5.0:unknown;4.1:unknown;3.0:unknown;2.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://symfony.com/roadmap
eol_cpes[ "cpe:/a:sensiolabs:symfony" ] = make_array(
  "versions",      "5.1:2021-01-31;5.0:2020-07-31;4.4:2023-11-30;4.3:2020-07-31;4.2:2020-01-31;4.1:2019-07-31;4.0:2019-01-31;3.4:2021-11-30;3.3:2018-07-31;3.2:2018-01-31;3.1:2017-07-31;3.0:2017-01-31;2.8:2019-11-30;2.7:2019-05-31;2.6:2016-01-31;2.5:2015-07-31;2.4:2015-01-31;2.3:2017-05-31;2.2:2014-05-31;2.1:2013-11-30;2.0:2013-09-30",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# General info on SolarWinds products:
# - Full overview: https://support.solarwinds.com/SuccessCenter/s/article/Currently-supported-software-versions?language=en_US
# - EOL dates are also partly announced via "EOL Announcements" in the current release notes like https://documentation.solarwinds.com/en/success_center/sem/content/release_notes/sem_2022-4_release_notes.htm
# - EOL EFFECTIVE DATE is used (at least for now)

# https://support.solarwinds.com/SuccessCenter/s/article/Currently-supported-software-versions?language=en_US#DPA
# https://documentation.solarwinds.com/en/success_center/dpa/content/release_notes/release_history.htm
eol_cpes[ "cpe:/a:solarwinds:database_performance_analyzer" ] = make_array(
  "versions",      "2023.1:2025-05-19;2022.4:2025-05-19;2022.3:2025-04-14;2022.2:2024-04-18;2022.1:2024-04-18;2021.3:2024-01-18;2021.1:2024-01-18;2020.2:2024-01-18;2019.4:2022-11-24;12.1:2022-11-24;12.0:2021-09-02;11.1:2021-09-02;11.0:2021-03-07;10.2:2019-11-26;10.1:2018-06-15;10.0:2018-06-15;9.2:2017-08-02;9.0:2017-05-02;8.3:2016-12-08",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://support.solarwinds.com/SuccessCenter/s/article/Currently-supported-software-versions?language=en_US#NCM
# Currently (as of 12/2023) the following is stated so these haven't been added here
# - Latest Version: 2023.4.2
# - Earliest Supported Version: 2020.2.5
eol_cpes[ "cpe:/a:solarwinds:network_configuration_manager" ] = make_array(
  "versions",      "2019.4:2023-08-26;8.0:2023-08-26;7.9:2022-07-15;7.8:2022-07-15;7.7:2020-09-06;7.6:2020-03-04;7.5:2018-12-14;2018;7.4:2018-06-15;7.3:2018-06-15;7.2:2018-06-15;7.1:2016-09-022;7.0:2015-08-31;6.0:2014-11-13;5.5:2014-01-01",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://support.solarwinds.com/SuccessCenter/s/article/Currently-supported-software-versions?language=en_US#SEM
eol_cpes[ "cpe:/a:solarwinds:security_event_manager" ] = make_array(
  "versions",      "2020.4:2023-10-19;2020.2:2023-10-19;2019.4:2023-10-19;6.7:2022-08-18;6.6:2021-09-06;6.5:2021-09-06;6.4:2021-09-04;6.3:2020-08-21;6.2:2019-12-12;6.1:2019-09-12;6.0:2017-11-16;5.7:2016-05-03;5.6:2015-09-10;5.5:2014-12-10;5.3:2014-06-11",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://support.sophos.com/support/s/article/KB-000039441
eol_cpes[ "cpe:/a:sophos:web_appliance" ] = make_array(
  "versions", "all:2023-07-20"
);

# https://kb.synology.com/en-us/WP/Synology_Security_White_Paper/3
eol_cpes[ "cpe:/a:synology:diskstation_manager" ] = make_array(
  "versions",      "6.1:2019-06-30;6.0:2018-06-30;5.2:2019-06-30;5.1:2016-12-31;5.0:2016-06-30;4.3:2015-12-31;4.2:2017-06-30;4.1:unknown;4.0:unknown;3.1:unknown;3.0:unknown;2.3:unknown;2.2:unknown;2.1:unknown;2.0:unknown;1.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://kb.synology.com/en-us/WP/Synology_Security_White_Paper/3
eol_cpes[ "cpe:/a:synology:router_manager" ] = make_array(
  "versions",      "1.1:2018-12-31;1.0:2017-12-31",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://docs.tenable.com/PDFs/product-lifecycle-management/tenable-software-release-lifecycle-matrix.pdf
# nb: The "End of Life Achieved/Last Day of Support" dates is used here
eol_cpes[ "cpe:/a:tenable:nessus" ] = make_array(
  "versions",      "10.6:2025-08-31;10.5:2025-03-31;10.4:2024-10-31;10.3:2024-07-31;10.2:2024-05-31;10.1:2024-01-31;10.0:2023-11-30;8.15:unknown;8.14:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://tiki.org/Versions#Version_Lifecycle
eol_cpes[ "cpe:/a:tiki:tikiwiki_cms%2fgroupware" ] = make_array(
  "versions",      "18:2023-01-31;15:2021-04-30;13:2015-11-30;12:2018-11-30;11:unknown;10:unknown;9:unknown;8:unknown;7:unknown;6:unknown;5:unknown;4:unknown;3:unknown;2:unknown;1:unknown",
  "version_regex", "^([0-9]+)"
);

# https://fluentbit.io/announcements/older-versions/
eol_cpes[ "cpe:/a:treasuredata:fluent_bit" ] = make_array(
  "versions",      "2.1:2024-02-06;2.0:2023-07-19;1.9:2022-12-05;1.8:2022-12-05;1.7:unknown;1.6:unknown;1.5:unknown;1.4:unknown;1.3:unknown;1.2:unknown;1.1:unknown;1.0:unknown;0.13:unknown;0.12:unknown;0.11:unknown;0.10:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://typo3.org/typo3-cms/roadmap/
# https://typo3.org/about/the-history-of-typo3/
eol_cpes[ "cpe:/a:typo3:typo3" ] = make_array(
  "versions",      "9:2021-10-31;8:2020-03-31;7:2018-11-31;6:2019-03-31;5:unknown;4:unknown;3:unknown",
  "version_regex", "^([0-9]+)"
);

# https://spring.io/projects/spring-boot#support
# https://github.com/spring-projects/spring-boot/wiki/Supported-Versions
#
# nb:
# - At least for Spring Boot 2.7 the vendor had moved around the EOL date and this should be checked
#   from time to time
# - The "End of OSS Support" dates should be used below, for the "End Enterprise Support" case the
#   common/2022/vmware/gb_spring_boot_eol.nasl VT contains a note to create an override.
#
eol_cpes[ "cpe:/a:vmware:spring_boot" ] = make_array(
  "versions",      "4.0:2026-12-31;3.5:2026-06-30;3.4:2025-12-31;3.3:2025-06-30;3.2:2024-12-31;3.1:2024-06-30;3.0:2023-12-31;2.7:2023-06-30;2.6:2022-11-24;2.5:2022-05-19;2.4:2021-11-18;2.3:2021-05-20;2.2:2020-10-16;2.1:2019-10-30;2.0:2019-03-01;1.5:2019-08-06;1.4:unknown;1.3:unknown;1.2:unknown;1.1:unknown;1.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://spring.io/projects/spring-framework#support
# https://github.com/spring-projects/spring-framework/wiki/Spring-Framework-Versions
#
# nb:
# - For all 4.x versions the EOL date of 4.3.x was used, similar with 3.x which got the EOL date of
#   3.2.x assigned
# - Other non-listed versions like 2.5 got extracted from the following URL and have a "unknown" EOL
#   date assigned: https://docs.spring.io/spring-framework/docs/
# - At least for Spring Boot 2.7 the vendor had moved around the EOL date and this can happen for
#   this product as well (it was the case for 5.3.x) and should be checked from time to time
# - The "End of OSS Support" dates should be used below, for the "End Enterprise Support" case the
#   common/2022/vmware/gb_spring_framework_eol_* VTs contains a note to create an override.
#
eol_cpes[ "cpe:/a:vmware:spring_framework" ] = make_array(
  "versions",      "7.9:2027-06-30;6.2:2026-06-30;6.1:2025-06-30;6.0:2024-06-30;5.3:2024-08-31;5.2:2021-12-31;5.1:2020-12-31;5.0:2020-12-31;4.3:2020-12-31;4.2:2020-12-31;4.1:2020-12-31;4.0:2020-12-31;3.2:2016-12-31;3.1:2016-12-31;3.0:2016-12-31;2.5:unknown;2.0:unknown;1.1:unknown;1.0:unknown",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://codex.wordpress.org/WordPress_Versions
# https://make.wordpress.org/security/2022/09/07/dropping-security-updates-for-wordpress-versions-3-7-through-4-0/
eol_cpes[ "cpe:/a:wordpress:wordpress" ] = make_array(
  "versions",      "4.0:2022-12-01;3.9:2022-12-01;3.8:2022-12-01;3.7:2022-12-01;3.6:2013-10-14;3.5:2013-08-01;3.4:2012-12-11;3.3:2012-06-27;3.2:2011-12-12;3.1:2011-07-04;3.0:2011-04-26;2.9:2010-06-17;2.8:2009-12-18;2.7:2009-06-10;2.6:2008-12-10;2.5:2008-07-15;2.3:2008-03-29;2.2:2007-09-24;2.1:2007-05-16;2.0:2007-08-05;1.5:2005-31-26;1.2:2005-02-17;1.0:2004-05-22;0.7:2004-01-03",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.zarafa.com/?
eol_cpes[ "cpe:/a:zarafa:zarafa" ] = make_array(
  "versions",      "7:2017-05-01;6:2017-05-01;5:2017-05-01;4:2017-05-01;3:2017-05-01;2:2017-05-01;1:2017-05-01",
  "version_regex", "^([0-9]+)"
);

# https://documentation.zarafa.com/zarafa_changelog/zcp.html
eol_cpes[ "cpe:/a:zarafa:zarafa_collaboration_platform" ] = make_array(
  "versions",      "7:2017-05-01;6:2017-05-01;5:2017-05-01;4:2017-05-01;3:2017-05-01;2:2017-05-01;1:2017-05-01",
  "version_regex", "^([0-9]+)"
);

# https://documentation.zarafa.com/zarafa_changelog/webapp.html
eol_cpes[ "cpe:/a:zarafa:webapp" ] = make_array(
  "versions",      "2:2017-05-01;1:2017-05-01",
  "version_regex", "^([0-9]+)"
);

# https://learn.microsoft.com/en-us/lifecycle/products/?terms=Silverlight
eol_cpes[ "cpe:/a:microsoft:silverlight" ] = make_array(
  "versions",      "5:2021-10-12;4:2013-01-08;3:2011-04-12;2:2010-10-12",
  "version_regex", "^([0-9]+)"
);
# https://devblogs.microsoft.com/dotnet/dotnet-7-end-of-support/
eol_cpes[ "cpe:/a:microsoft:asp.net_core" ] = make_array(
   "versions",     "7.0.0:2024-05-14;7.0.1:2024-05-14;7.0.2:2024-05-14;7.0.3:2024-05-14;7.0.4:2024-05-14;7.0.5:2024-05-14;7.0.6:2024-05-14;7.0.7:2024-05-14;7.0.8:2024-05-14;7.0.9:2024-05-14;7.0.10:2024-05-14;7.0.11:2024-05-14;7.0.12:2024-05-14;7.0.13:2024-05-14;7.0.14:2024-05-14;7.0.15:2024-05-14;7.0.16:2024-05-14;7.0.17:2024-05-14;7.0.18:2024-05-14;7.0.19:2024-05-14;7.0.20:2024-05-14",
   "version_regex", "^([0-9]+)"
);

# https://forums.ivanti.com/s/article/Product-End-of-Support-End-of-Engineering-Schedule-Pulse-Secure-Traffic-Manager-vTM
eol_cpes[ "cpe:/a:ivanti:virtual_traffic_manager" ] = make_array(
  "versions",      "22.7:2026-05-26;22.2:2026-07-19;22.6:2025-10-04;22.5:2025-07-20;22.3:2025-01-17;22.3:2024-10-24;22.1:2024-04-21;21.4:2024-01-18;21.3:2023-10-12;21.2:2023-08-02;21.1:2023-04-21;20.3:2023-02-08;20.2:2022-07-15;20.1:2024-03-16;19.3:2021-10-15;19.2:2023-07-15;19.1:2021-04-29;18.3:2020-11-26;18.2:2022-08-01;18.1:2020-03-02;17.4:2019-10-09;17.3:2019-07-03;17.2:2021-05-22;17.1:2019-01-23;11.1:2018-10-17;10.4:2020-03-29;10.3:2017-12-14;10.2:2017-10-26;10.1:2017-07-22;10.0:2017-04-13;9.9:2019-01-06;9.8:2016-03-22;9.7:2016-02-04;9.6:2016-01-28;9.5:2016-01-28;9.4:2016-01-28;9.3:2016-01-28;9.2:2015-10-28;9.1:2015-10-28;9.0:2015-10-28;8.1:2015-10-28;8.0:2015-10-28",
  "version_regex", "^([0-9]+\.[0-9]+)"
);

# https://www.zimbra.com/product/product-lifecycle/
# https://wiki.zimbra.com/wiki/Zimbra_Releases
eol_cpes[ "cpe:/a:zimbra:collaboration" ] = make_array(
  "versions",      "10.1:2027-12-31;10.0:2025-12-31;9.0:2025-06-30;8.8:2024-12-31;8.7:2019-12-31;8.6:2019-09-30;8.5:2018-09-30;8.0:2017-09-10",
  "version_regex", "^([0-9]+\.[0-9]+)"
);


# @brief Checks and reports if a specific given CPE and version has reached it's End of Life (EOL).
#        To conduct the check check_version_string is called.
#
# @param cpe     A valid CPE of a product to be checked in the form of:
#                "cpe:/[aoh]:vendor_component:product_component"
#                but without any version or additional parts included
#
# @param version The version of the given application to be checked
#
# @param debug   If set to TRUE additional debug logging is shown on the console
#
# @note A given CPE needs to be included in the eol_cpes[] array of this include (see existing
#       examples as otherwise no EOL reporting will happen.
#
# @note See the "cpe:/a:jetbrains:upsource" example on how to mark a whole product EOL (independent
#       from the installed version) at a specific date.
#
# @return NULL if not all mandatory parameters have been given, no EOL data has been included in
#         this include yet or the specific product hasn't reached it's EOL yet. An array containing
#         the following array indices if the product has reached it's EOL:
#
#         ret_array["eol_version"] = The found EOL version
#         ret_array["eol_date"] =    The date the version has reached it's EOL
#
function product_reached_eol( cpe, version, debug ) {

  local_var cpe, version, debug, eol_array, retValue;

  if( ! cpe ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#product_reached_eol" );
    return;
  }

  if( ! eol_cpes[ cpe ] ) {
    if( debug ) display( "DEBUG: CPE " + cpe + " not in eol_cpes array." );
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#CPE '" + cpe + "' passed to cpe parameter of product_reached_eol is not in the list of EOL products" );
    return;
  }

  if( ! version ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#product_reached_eol" );
    return;
  }

  eol_array = eol_cpes[ cpe ];

  if( ! is_array( eol_array ) )
    return;

  # n.b. Does not need foreach as existence of this array entry is enough
  if( ! eol_array[ "versions" ] ) {
    if( debug ) display( "DEBUG: eol_cpes array doesn't contain a 'versions' statement." );
    return;
  }

  if( is_array( eol_array["version_regex"] ) ){
    for( i=0; i < max_index( eol_array["version_regex"] ); i++) {
      version_regex_list = eol_array["version_regex"];
      version_list = eol_array[ "versions" ];

      retValue = check_version_string( version_regex:version_regex_list[i],version_string:version_list[i],
                            cpe:cpe, version:version, debug:debug);
      if( is_array( retValue ) ) {
        return retValue;
      }
    }
    return retValue;
  } else {
    return check_version_string( version_regex:eol_array["version_regex"], version_string:eol_array["versions"],
                                 cpe:cpe, version:version, debug:debug );
  }
}


# @brief Conducts the version check using the versions string and version_regex
#
# @param version_regex The specific regex which is used to extract the version from the parameter version.
#
# @param version_string A string which contains all versions with their respective EOL date.
#
# @param cpe     A valid CPE of a product to be checked in the form of:
#                "cpe:/[aoh]:vendor_component:product_component"
#                but without any version or additional parts included
#
# @param version The version of the given application to be checked
#
# @param debug   If set to TRUE additional debug logging is shown on the console#
#
# @return NULL if not all mandatory parameters have been given, no EOL data has been included in
#         this include yet or the specific product hasn't reached it's EOL yet. An array containing
#         the following array indices if the product has reached it's EOL:
#
#         ret_array["eol_version"] = The found EOL version
#         ret_array["eol_date"] =    The date the version has reached it's EOL
#
function check_version_string( version_regex, version_string, cpe, version, debug ){
  local_var version_regex, version_string, cpe, version, debug, v, test_versions, _tv, test_version, eol_date, v_d;
  if( version_regex ) {
    v = eregmatch( pattern:version_regex, string:version );
    if( isnull( v[0] ) ) {
      if( debug ) display( "DEBUG: Passed version_regex: " + version_regex + " doesn't match version : " + version + " . No EOL version identified." );
      return;
    } else {
      if( debug ) display( "DEBUG: Passed version_regex: " + version_regex + " is matching : " + version + " ." );
      version = v[0];
    }
  }

  test_versions = split( version_string, sep:";", keep:FALSE );
  if( ! is_array( test_versions ) ) {
    if( debug ) display( "DEBUG: versions of " + cpe + " couldn't be split into an array." );
    return;
  }

  if( debug ) display( "DEBUG: versions/dates of " + cpe + " used for this test: " + test_versions );

  foreach _tv( test_versions ) {

    test_version = "";
    eol_date     = "";

    v_d = eregmatch( pattern:"^([^:]+):(.+)$", string:_tv );
    if( isnull( v_d[1] ) || isnull( v_d[2] ) ) {
      if( debug ) display( "DEBUG: eol_cpes array has a wrong 'version:date' syntax." );
      return;
    }

    test_version = v_d[1];
    eol_date     = v_d[2];
    if( debug ) display( "DEBUG: Current product version: '" + version + "' tested with an exact match against EOL version '" + test_version + "' and EOL date '" + eol_date + "' (unknown means instantly EOL)" );

    if( version == test_version ||
        test_version == "all" ) { # nb: Special case, we just mark all versions EOL at this date
      if( eol_date_reached( eol_date:eol_date ) ) {
        return make_array( "eol_version", test_version,
                           "eol_date",    eol_date );
      }
    }
  }

  return;
}
