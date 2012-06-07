#!/usr/bin/perl

#-# if eth0 isn't the name of your primary interface, change the reference here
$OURDIR="/home/bind/safedns";
$IP=`/sbin/ifconfig eth0 | grep "inet addr" | sed 's/.*addr://' | sed 's/ *Bcast.*//'`;
chomp $IP;

if ($IP !~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
  die "Could not determine my IP address - ifconfig returned: $IP\n";
  }
else {
  print "Setting IP to $IP\n";
  }

$DEBUG = 1;
if ($DEBUG) {
  open (DEBUG, ">$OURDIR/debug.log") 
	|| die "Cannot open $OURDIR/debug.log: $!\n";
  }

$new_domains_ok = compare();
if (!$new_domains_ok) {
  print DEBUG "New and previous domain lists differ more than 25% - exiting without update.\n";
  close(DEBUG);
  die "New and previous domain lists differ more than 25% - exiting without update.\n";
  }


# initialize 
use DBI;
use Time::Local;

$db = "malware_domains"; 
$host = "localhost";
$user = "bind";
$pass = "xxxxxxxxxx"; #-# set to actual password for bind user in MySQL

# hostname and IP address of first record to insert if database empty
# e.g. the hostname where BIND is running
$seed_host = 'safedns.school.edu'; #-#
$seed_ip = $IP;

# connect to local MySQL database
$dbh = DBI->connect("DBI:mysql:database=$db;host=$host;mysql_server_prepare=1",
                      $user, $pass, {RaiseError => 1});

# see which table needs updating 
# (dns_records_1 and dns_records_2 get populated alternately)
$oldest_table = cmp_table_ages($dbh);
print "Oldest table: $oldest_table\n";

# count number of records prior to any changes, adding seed record if needed
$rowsatbegin = initial_ize_table($dbh, $oldest_table);

print "Inserting malware domain records...\n";
while(<>) {
  # make sure domain name is RFC-compliant
  next unless /^((\w([\w\-]{0,61}\w)?\.)*\w([\w\-]{0,61}\w)?)$/;
  $domain = $1;
  if (length($domain) > 253) { next; } # ignore if over max length
  $sth=$dbh->prepare("call malware_domains.insert_$oldest_table('$domain', '$IP')") || die $DBI::err.": ".$DBI::errstr;
  $sth->execute || die DBI::err.": ".$DBI::errstr; 
  if ($DEBUG) {
    $sth=$dbh->prepare("select row_count()") || die $DBI::err.": ".$DBI::errstr;
    $sth->execute || die DBI::err.": ".$DBI::errstr; 
    my $count = $sth->fetchrow_arrayref;
    print DEBUG "$$count[0] inserted for $domain\n";
    }
  }

# count number of records after changes

$sth=$dbh->prepare("select count(*) from dns_records_$oldest_table") || die $DBI::err.": ".$DBI::errstr;
$sth->execute || die DBI::err.": ".$DBI::errstr; 
my $postcount = $sth->fetchrow_arrayref;
my $rowsatend = $$postcount[0];
print "Rows at end: $rowsatend\n";
$sth->finish();

$dbh->disconnect();

# Make sure number of rows hasn't changed too much. If all seems okay,
# write to a file which table was updated, so update_malware_domains.sh
# can point BIND to it
$table_flag = "$OURDIR/dns_table_updated";
open(RESULT, ">$table_flag") || die "Cannot open $table_flag: $!\n";
if ($rowsatbegin) { 
  $pct_change = abs($rowsatend - $rowsatbegin)/$rowsatbegin; 
  if ($pct_change < 0.25) { 
    print "$table_flag: table $oldest_table was updated.\n";
    print RESULT $oldest_table;
    }
  else {
    print "$table_flag: anomalous change to malware domain list.\n";
    print RESULT 0;
    }
  }
elsif ($rowsatend) { # no rows at beginning, but now we have some, so go ahead
  print "$table_flag: no rows at beginning, some now in $oldest_table.\n";
  print RESULT $oldest_table;
  }
else { 
  print "$table_flag: no rows at beginning or end. so no point restarting.\n";
  print RESULT 0;
  }
close(RESULT);
close(DEBUG);

# Compare current and previous versions of malwaredomains file
# to determine if we should proceed with loading domain list in database.
# If previous version doesn't exist, proceed with load. Otherwise,
# load if number of malware domains differs by less than 25% from the
# previous day's load.
sub compare {
  if (!open(PREV, "$OURDIR/malwaredomains.prev")) { return 1; }
  else { close(PREV); }

  $prevcount = `/bin/cat $OURDIR/malwaredomains.prev | /usr/bin/wc -l`;
  chomp $prevcount;
  $currcount = `/bin/cat $OURDIR/malwaredomains | /usr/bin/wc -l`;
  chomp $currcount;

  $pct_change = abs($currcount - $prevcount)/$prevcount;
  if ($pct_change < 0.25) { return 1; }
  else { return 0; }
  }

# need a seed record with a certain format, otherwise subsequent inserts fail

sub insert_seed {
  my $tnum = $_[0];
  $stmt = "insert into dns_records_$tnum (zone, host, type, data, mx_priority) \n";
  $stmt .= "values ('$seed_host', '*', 'A', '$seed_ip', null)\n";
  $sth=$dbh->prepare($stmt) || die $DBI::err.": ".$DBI::errstr;
  $sth->execute || die DBI::err.": ".$DBI::errstr;
  $sth=$dbh->prepare("select row_count()") || die $DBI::err.": ".$DBI::errstr;
  $sth->execute || die DBI::err.": ".$DBI::errstr;
  my $count = $sth->fetchrow_arrayref;
  return $$count[0];
  }

# Given YYYY-MM-DD HH:MM:SS localtime, return local UNIX timestamp.

sub unfmt_time {
  my $ftime = $_[0];
  if ($ftime =~ /([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})/) {
    return timelocal($6,$5,$4,$3,$2-1,$1);
    }
  }

# Given two arguments (time, formatted like YYYY-MM-DD HH:MM:SS) return
# 1 if it's the oldest, otherwise return 2.

sub find_oldest {
  my ($time1, $time2) = @_;
  $ts1 = unfmt_time($time1);
  $ts2 = unfmt_time($time2);
  if ($ts1 < $ts2) { return 1; }
  else { return 2; }
  }

sub cmp_table_ages {
  my $dbh = @_[0];
  # get last updated date for dns_records_1
  $sth=$dbh->prepare("select update_time from information_schema.tables where table_schema = 'malware_domains' and table_name = 'dns_records_1'") || die $DBI::err.": ".$DBI::errstr;
  $sth->execute || die DBI::err.": ".$DBI::errstr; 
  my $update_1 = $sth->fetchrow_arrayref;
  print "dns_records_1 last updated: $$update_1[0]\n";
  # get last updated date for dns_records_2
  $sth=$dbh->prepare("select update_time from information_schema.tables where table_schema = 'malware_domains' and table_name = 'dns_records_2'") || die $DBI::err.": ".$DBI::errstr;
  $sth->execute || die DBI::err.": ".$DBI::errstr; 
  my $update_2 = $sth->fetchrow_arrayref;
  print "dns_records_2 last updated: $$update_2[0]\n";
  
  return find_oldest($$update_1[0], $$update_2[0]);
  }

sub initial_ize_table {
  my ($dbh, $tnum) = @_;
  # Count rows at start
  $sth=$dbh->prepare("select count(*) from dns_records_$tnum") || die $DBI::err.": ".$DBI::errstr;
  $sth->execute || die DBI::err.": ".$DBI::errstr; 
  my $precount = $sth->fetchrow_arrayref;
  print "Rows at begin: $$precount[0]\n";
  my $oldrows = $$precount[0];

  # Delete all rows from dns_records_$tnum (oldest of two dns_records tables)
  $sth=$dbh->prepare("delete from dns_records_$tnum") || die $DBI::err.": ".$DBI::errstr;
  $sth->execute || die DBI::err.": ".$DBI::errstr; 

  if ($$precount[0] == 0) { # insert record for safedns to next inserts succeed
    $inserted = insert_seed($tnum);
    print "Number of seed row(s) inserted: $inserted\n";
    if (!$inserted) { die "Could not insert seed record into MySQL - fatal!\n"; }
    $$precount[0] = 1;
    }
  else { 
    print "dns_records_$tnum has $$precount[0] records - no seed inserted\n";
    }
  return $oldrows;
  }

